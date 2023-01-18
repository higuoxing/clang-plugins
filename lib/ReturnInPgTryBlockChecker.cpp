//==============================================================================
// FILE:
//    ReturnInPgTryBlockChecker.cpp
//
// DESCRIPTION:
//    Check if there's a return statement in the PG_TRY() block. Using return
//    statements in PG_TRY() block will break error stacks.
//
// USAGE:
//   clang -cc1 -load <BUILD_DIR>/lib/libReturnInPgTryBlockChecker.so '\'
//    -plugin alpha.postgres.ReturnInPgTryBlockChecker test.c
//
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
#include "clang/Basic/Diagnostic.h"
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

#include <queue>
#include <unordered_set>

using namespace clang;
using namespace ento;
using namespace clang::ast_matchers;

static void CheckUnsafeBreakStmt(const Stmt *Then, ASTContext *Ctx) {
  std::queue<const Stmt *> StmtQueue;
  StmtQueue.push(Then);
  while (!StmtQueue.empty()) {
    const Stmt *CurrStmt = StmtQueue.front();
    StmtQueue.pop();

    if (!CurrStmt)
      continue;

    if (const BreakStmt *Break =
            llvm::dyn_cast_if_present<BreakStmt>(CurrStmt)) {
      // We've found a break statement inside PG_TRY block. Let's warn
      // about it.
      DiagnosticsEngine &DE = Ctx->getDiagnostics();
      unsigned DiagID = DE.getCustomDiagID(
          DiagnosticsEngine::Error,
          "break statement is used inside PG_TRY block which is unsafe");
      auto DB = DE.Report(Break->getBreakLoc(), DiagID);
      DB.AddSourceRange(CharSourceRange::getCharRange(Break->getSourceRange()));
    }

    // break stataments in while/do-while/for/switch statements are safe.
    if (llvm::isa<WhileStmt>(CurrStmt) || llvm::isa<DoStmt>(CurrStmt) ||
        llvm::isa<ForStmt>(CurrStmt) || llvm::isa<SwitchStmt>(CurrStmt)) {
      continue;
    }

    for (const Stmt *C : CurrStmt->children()) {
      StmtQueue.push(C);
    }
  }
}

static void CheckUnsafeContinueStmt(const Stmt *Then, ASTContext *Ctx) {
  std::queue<const Stmt *> StmtQueue;
  StmtQueue.push(Then);
  while (!StmtQueue.empty()) {
    const Stmt *CurrStmt = StmtQueue.front();
    StmtQueue.pop();

    if (!CurrStmt)
      continue;

    if (const ContinueStmt *Continue =
            llvm::dyn_cast_if_present<ContinueStmt>(CurrStmt)) {
      // We've found a continue statement inside PG_TRY block. Let's warn
      // about it.
      DiagnosticsEngine &DE = Ctx->getDiagnostics();
      unsigned DiagID = DE.getCustomDiagID(
          DiagnosticsEngine::Error,
          "continue statement is used inside PG_TRY block which is unsafe");
      auto DB = DE.Report(Continue->getContinueLoc(), DiagID);
      DB.AddSourceRange(
          CharSourceRange::getCharRange(Continue->getSourceRange()));
    }

    // continue stataments in while/do-while/for statements are safe.
    if (llvm::isa<WhileStmt>(CurrStmt) || llvm::isa<DoStmt>(CurrStmt) ||
        llvm::isa<ForStmt>(CurrStmt)) {
      continue;
    }

    for (const Stmt *C : CurrStmt->children()) {
      StmtQueue.push(C);
    }
  }
}

static void CheckUnsafeGotoStmt(const Stmt *Then, ASTContext *Ctx) {
  std::queue<const Stmt *> StmtQueue;
  std::unordered_set<const LabelStmt *> LabelDecls;
  std::unordered_set<const GotoStmt *> GotoStmts;
  StmtQueue.push(Then);
  while (!StmtQueue.empty()) {
    const Stmt *CurrStmt = StmtQueue.front();
    StmtQueue.pop();

    if (!CurrStmt)
      continue;

    if (const LabelStmt *Label =
            llvm::dyn_cast_if_present<LabelStmt>(CurrStmt)) {
      LabelDecls.insert(Label);
    } else if (const GotoStmt *Goto =
                   llvm::dyn_cast_if_present<GotoStmt>(CurrStmt)) {
      GotoStmts.insert(Goto);
    }

    for (const Stmt *C : CurrStmt->children()) {
      StmtQueue.push(C);
    }
  }

  // Iterate over GotoStmts to check if we're jumping out of PG_TRY block.
  for (const GotoStmt *Goto : GotoStmts) {
    if (!Goto->getLabel() || LabelDecls.count(Goto->getLabel()->getStmt()))
      continue;
    DiagnosticsEngine &DE = Ctx->getDiagnostics();
    unsigned DiagID =
        DE.getCustomDiagID(DiagnosticsEngine::Error,
                           "unsafe goto statement is used inside PG_TRY block");
    auto DB = DE.Report(Goto->getGotoLoc(), DiagID);
    DB.AddSourceRange(CharSourceRange::getCharRange(Goto->getSourceRange()));
  }
}

class PgTryBlockMatcherCallback : public MatchFinder::MatchCallback {
public:
  PgTryBlockMatcherCallback() = default;

  void run(const MatchFinder::MatchResult &Result) override {
    ASTContext *Ctx = Result.Context;

    if (const ReturnStmt *Return =
            Result.Nodes.getNodeAs<ReturnStmt>("ReturnInPgTryBlock")) {
      // We've found a return statement inside PG_TRY block. Let's warn about
      // it.
      DiagnosticsEngine &DE = Ctx->getDiagnostics();
      unsigned DiagID = DE.getCustomDiagID(
          DiagnosticsEngine::Error,
          "unsafe return statement is used inside PG_TRY block");
      auto DB = DE.Report(Return->getReturnLoc(), DiagID);
      DB.AddSourceRange(
          CharSourceRange::getCharRange(Return->getSourceRange()));
    } else if (const IfStmt *If =
                   Result.Nodes.getNodeAs<IfStmt>("PgTryBlock")) {
      const Stmt *Then = If->getThen();
      CheckUnsafeBreakStmt(Then, Ctx);
      CheckUnsafeContinueStmt(Then, Ctx);
      CheckUnsafeGotoStmt(Then, Ctx);
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
                // }
                binaryOperator(allOf(hasOperatorName("=="),
                                     hasOperands(callExpr(callee(functionDecl(
                                                     hasName("__sigsetjmp")))),
                                                 integerLiteral(equals(0)))))),
            hasThen(eachOf(
                forEachDescendant(returnStmt().bind("ReturnInPgTryBlock")),
                anyOf(hasDescendant(breakStmt()), hasDescendant(continueStmt()),
                      hasDescendant(gotoStmt())))))
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
      /*Desc=*/
      "Check if there're unsafe return/continue/break/goto statements in "
      "PG_TRY block",
      /*DocsUri=*/"");
}
