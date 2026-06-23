#include "ReturnInPgTryBlockCheck.h"
#include "clang/AST/ASTContext.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include <queue>
#include <unordered_set>

using namespace clang::ast_matchers;

namespace clang {
namespace tidy {
namespace postgres {

static void CheckUnsafeBreakStmt(const Stmt *Then, ClangTidyCheck &Check, ASTContext *Ctx) {
  std::queue<const Stmt *> StmtQueue;
  StmtQueue.push(Then);
  while (!StmtQueue.empty()) {
    const Stmt *CurrStmt = StmtQueue.front();
    StmtQueue.pop();

    if (!CurrStmt)
      continue;

    if (const BreakStmt *Break =
            llvm::dyn_cast_if_present<BreakStmt>(CurrStmt)) {
      Check.diag(Break->getBreakLoc(), "break statement is used inside PG_TRY block which is unsafe");
    }

    // break statements in while/do-while/for/switch statements are safe.
    if (llvm::isa<WhileStmt>(CurrStmt) || llvm::isa<DoStmt>(CurrStmt) ||
        llvm::isa<ForStmt>(CurrStmt) || llvm::isa<SwitchStmt>(CurrStmt)) {
      continue;
    }

    for (const Stmt *C : CurrStmt->children()) {
      StmtQueue.push(C);
    }
  }
}

static void CheckUnsafeContinueStmt(const Stmt *Then, ClangTidyCheck &Check, ASTContext *Ctx) {
  std::queue<const Stmt *> StmtQueue;
  StmtQueue.push(Then);
  while (!StmtQueue.empty()) {
    const Stmt *CurrStmt = StmtQueue.front();
    StmtQueue.pop();

    if (!CurrStmt)
      continue;

    if (const ContinueStmt *Continue =
            llvm::dyn_cast_if_present<ContinueStmt>(CurrStmt)) {
      Check.diag(Continue->getContinueLoc(), "continue statement is used inside PG_TRY block which is unsafe");
    }

    // continue statements in while/do-while/for statements are safe.
    if (llvm::isa<WhileStmt>(CurrStmt) || llvm::isa<DoStmt>(CurrStmt) ||
        llvm::isa<ForStmt>(CurrStmt)) {
      continue;
    }

    for (const Stmt *C : CurrStmt->children()) {
      StmtQueue.push(C);
    }
  }
}

static void CheckUnsafeGotoStmt(const Stmt *Then, ClangTidyCheck &Check, ASTContext *Ctx) {
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

  for (const GotoStmt *Goto : GotoStmts) {
    if (!Goto->getLabel() || LabelDecls.count(Goto->getLabel()->getStmt()))
      continue;
    Check.diag(Goto->getGotoLoc(), "unsafe goto statement is used inside PG_TRY block");
  }
}

void ReturnInPgTryBlockCheck::registerMatchers(MatchFinder *Finder) {
  StatementMatcher PgTry =
      ifStmt(
          hasCondition(
              binaryOperator(allOf(hasOperatorName("=="),
                                   hasOperands(callExpr(callee(functionDecl(
                                                   hasName("__sigsetjmp")))),
                                               integerLiteral(equals(0)))))),
          hasThen(eachOf(
              forEachDescendant(returnStmt().bind("ReturnInPgTryBlock")),
              anyOf(hasDescendant(breakStmt()), hasDescendant(continueStmt()),
                    hasDescendant(gotoStmt())))))
          .bind("PgTryBlock");

  Finder->addMatcher(PgTry, this);
}

void ReturnInPgTryBlockCheck::check(const MatchFinder::MatchResult &Result) {
  ASTContext *Ctx = Result.Context;

  if (const auto *Return =
          Result.Nodes.getNodeAs<ReturnStmt>("ReturnInPgTryBlock")) {
    diag(Return->getReturnLoc(), "unsafe return statement is used inside PG_TRY block");
  } else if (const auto *If =
                 Result.Nodes.getNodeAs<IfStmt>("PgTryBlock")) {
    const Stmt *Then = If->getThen();
    CheckUnsafeBreakStmt(Then, *this, Ctx);
    CheckUnsafeContinueStmt(Then, *this, Ctx);
    CheckUnsafeGotoStmt(Then, *this, Ctx);
  }
}

} // namespace postgres
} // namespace tidy
} // namespace clang
