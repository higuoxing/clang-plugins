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
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/Basic/FileManager.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Frontend/FrontendPluginRegistry.h"
#include "llvm/ADT/StringMap.h"
#include "llvm/Support/raw_ostream.h"
#include <clang/AST/ASTContext.h>
#include <clang/AST/Expr.h>
#include <clang/AST/Stmt.h>
#include <clang/ASTMatchers/ASTMatchFinder.h>
#include <clang/ASTMatchers/ASTMatchers.h>
#include <clang/ASTMatchers/ASTMatchersInternal.h>
#include <clang/Basic/SourceLocation.h>
#include <clang/Basic/SourceManager.h>
#include <llvm/Support/Casting.h>

using namespace clang;

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

class PgTryBlockMatcherCallback
    : public ast_matchers::MatchFinder::MatchCallback {
public:
  PgTryBlockMatcherCallback() = default;

  void run(const ast_matchers::MatchFinder::MatchResult &Result) override {
    ASTContext *Ctx = Result.Context;

    if (const ReturnStmt *Return =
            Result.Nodes.getNodeAs<ReturnStmt>("ReturnInPgTry")) {
      // We've found a returnStmt inside PG_TRY block. Let's warn about it.
      DiagnosticsEngine &DE = Ctx->getDiagnostics();
      unsigned DiagID = DE.getCustomDiagID(
          DiagnosticsEngine::Warning,
          "(AST Matcher) return statement is used inside PG_TRY block");
      auto DB = DE.Report(Return->getReturnLoc(), DiagID);
      DB.AddSourceRange(
          CharSourceRange::getCharRange(Return->getSourceRange()));
    }
  }
};

//-----------------------------------------------------------------------------
// ASTConsumer
//-----------------------------------------------------------------------------
class ReturnInPgTryBlockASTConsumer : public ASTConsumer {
public:
  ReturnInPgTryBlockASTConsumer(ASTContext &Ctx, SourceManager &SM)
      : SM(SM), PgTryVisitor(&Ctx) {
    ast_matchers::StatementMatcher PgTry =
        ast_matchers::ifStmt(
            ast_matchers::hasCondition(
                // PG_TRY() will be expanded to the following expression.
                // if (__sigsetjmp() == 0) {
                //   any expression that contains return;
                // }
                ast_matchers::binaryOperator(ast_matchers::allOf(
                    ast_matchers::hasOperatorName("=="),
                    ast_matchers::hasOperands(
                        ast_matchers::callExpr(
                            ast_matchers::callee(ast_matchers::functionDecl(
                                ast_matchers::hasName("__sigsetjmp")))),
                        ast_matchers::integerLiteral(
                            ast_matchers::equals(0)))))),
            ast_matchers::hasThen(ast_matchers::hasDescendant(
                ast_matchers::returnStmt().bind("ReturnInPgTry"))))
            .bind("PgTryBlock");

    TUMatcher.addMatcher(PgTry, &PgTryMatcherCallback);
  }

  void HandleTranslationUnit(ASTContext &Ctx) override {
    TUMatcher.matchAST(Ctx);

    auto Decls = Ctx.getTranslationUnitDecl()->decls();
    for (auto &Decl : Decls) {
      if (!SM.isInMainFile(Decl->getLocation()))
        continue;

      PgTryVisitor.TraverseDecl(Decl);
    }
  }

private:
  ast_matchers::MatchFinder TUMatcher;
  SourceManager &SM;

  PgTryBlockMatcherCallback PgTryMatcherCallback;
  ReturnInPgTryBlockASTVisitor PgTryVisitor;
};

//-----------------------------------------------------------------------------
// FrontendAction for ReturnInPgTryBlockChecker
//-----------------------------------------------------------------------------
class ReturnInPgTryBlockPluginASTAction : public PluginASTAction {
public:
  std::unique_ptr<ASTConsumer>
  CreateASTConsumer(CompilerInstance &CI, llvm::StringRef InFile) override {
    return std::unique_ptr<ASTConsumer>(
        std::make_unique<ReturnInPgTryBlockASTConsumer>(CI.getASTContext(),
                                                        CI.getSourceManager()));
  }

  bool ParseArgs(const CompilerInstance &CI,
                 const std::vector<std::string> &args) override {
    return true;
  }
};

//-----------------------------------------------------------------------------
// Registration
//-----------------------------------------------------------------------------
extern "C" __attribute__((visibility("default")))
const char clang_analyzerAPIVersionString[] = "16.0.0";

static FrontendPluginRegistry::Add<ReturnInPgTryBlockPluginASTAction>
    X(/*Name=*/"alpha.postgres.ReturnInPgTryBlockChecker",
      /*Description=*/"Check if there're return statements in PG_TRY block");
