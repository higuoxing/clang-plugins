//==============================================================================
// FILE:
//    HelloWorld.cpp
//
// DESCRIPTION:
//    Counts the number of C++ record declarations in the input translation
//    unit. The results are printed on a file-by-file basis (i.e. for each
//    included header file separately).
//
//    Internally, this implementation leverages llvm::StringMap to map file
//    names to the corresponding #count of declarations.
//
// USAGE:
//   clang -cc1 -load <BUILD_DIR>/lib/libHelloWorld.dylib '\'
//    -plugin hello-world test/HelloWorld-basic.cpp
//
// License: The Unlicense
//==============================================================================
#include "clang/AST/ASTConsumer.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/Stmt.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/ASTMatchers/ASTMatchers.h"
#include "clang/ASTMatchers/ASTMatchersInternal.h"
#include "clang/Basic/FileManager.h"
#include "clang/Basic/SourceLocation.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "llvm/ADT/StringMap.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/raw_ostream.h"

using namespace clang;
using namespace ento;
using namespace clang::ast_matchers;

//-----------------------------------------------------------------------------
// RecursiveASTVisitor
//-----------------------------------------------------------------------------
class ReturnInPgTryBlockASTVisitor
    : public RecursiveASTVisitor<ReturnInPgTryBlockASTVisitor> {
public:
  explicit ReturnInPgTryBlockASTVisitor(ASTContext *Context)
      : Context(Context) {}

private:
  ASTContext *Context;
};

class PgTryBlockMatcherCallback : public MatchFinder::MatchCallback {
public:
  PgTryBlockMatcherCallback() = default;

  void run(const MatchFinder::MatchResult &Result) override {
    ASTContext *Ctx = Result.Context;

    if (const ReturnStmt *Return =
            Result.Nodes.getNodeAs<ReturnStmt>("ReturnInPgTryCatch")) {
      // We've found a returnStmt inside PG_TRY block. Let's warn about it.
      DiagnosticsEngine &DE = Ctx->getDiagnostics();
      unsigned DiagID = DE.getCustomDiagID(
          DiagnosticsEngine::Error,
          "return statement is used inside PG_TRY-PG_CATCH block");
      auto DB = DE.Report(Return->getReturnLoc(), DiagID);
      DB.AddSourceRange(
          CharSourceRange::getCharRange(Return->getSourceRange()));
    }
  }
};

namespace {
class ReturnInPgTryBlockChecker : public Checker<check::EndOfTranslationUnit> {
public:
  void checkEndOfTranslationUnit(const TranslationUnitDecl *TU,
                                 AnalysisManager &AM, BugReporter &B) const {
    MatchFinder F;
    PgTryBlockMatcherCallback CB;
    StatementMatcher PgTry =
        ifStmt(
            hasCondition(
                // PG_TRY() will be expanded to the following expression.
                // if (__sigsetjmp() == 0) {
                //   any expression that contains return;
                // }
                binaryOperator(allOf(hasOperatorName("=="),
                                     hasOperands(callExpr(callee(functionDecl(
                                                     hasName("__sigsetjmp")))),
                                                 integerLiteral(equals(0)))))),
            hasDescendant(returnStmt().bind("ReturnInPgTryCatch")))
            .bind("PgTryBlock");

    F.addMatcher(PgTry, &CB);
    F.matchAST(TU->getASTContext());
  }
};
} // namespace

//-----------------------------------------------------------------------------
// Registration
//-----------------------------------------------------------------------------
extern "C" __attribute__((visibility("default")))
const char clang_analyzerAPIVersionString[] = "16.0.0";

extern "C" __attribute__((visibility("default"))) void
clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<ReturnInPgTryBlockChecker>(
      /*FullName=*/"alpha.postgres.ReturnInPgTryBlockChecker",
      /*Desc=*/"Check if there're return statements in PG_TRY-PG_CATCH block",
      /*DocsUri=*/"");
}
