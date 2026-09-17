#include "UnbalancedHoldInterruptsCheck.h"

#include "clang/AST/ASTContext.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"

using namespace clang::ast_matchers;

namespace clang {
namespace tidy {
namespace postgres {
namespace {

enum class Counter { Hold, Cancel };

struct RegionState {
  int Hold = 0;
  int Cancel = 0;
};

struct ResumeAfter {
  bool Hold = false;
  bool Cancel = false;
};

bool isLiteralZero(const Expr *E) {
  if (!E)
    return false;
  E = E->IgnoreParenImpCasts();
  if (const auto *IL = dyn_cast<IntegerLiteral>(E))
    return IL->getValue().isZero();
  return false;
}

bool refersToCounter(const Expr *E, Counter C) {
  if (!E)
    return false;
  const auto *DRE = dyn_cast<DeclRefExpr>(E->IgnoreParenCasts());
  if (!DRE)
    return false;
  const StringRef Name = DRE->getDecl()->getName();
  return C == Counter::Hold ? Name == "InterruptHoldoffCount"
                            : Name == "QueryCancelHoldoffCount";
}

const Stmt *unwrap(const Stmt *S) {
  while (S) {
    if (const auto *E = dyn_cast<Expr>(S))
      S = E->IgnoreParenCasts();
    if (const auto *L = dyn_cast<LabelStmt>(S)) {
      S = L->getSubStmt();
      continue;
    }
    if (const auto *C = dyn_cast<CaseStmt>(S)) {
      S = C->getSubStmt();
      continue;
    }
    if (const auto *D = dyn_cast<DefaultStmt>(S)) {
      S = D->getSubStmt();
      continue;
    }
    if (const auto *A = dyn_cast<AttributedStmt>(S)) {
      S = A->getSubStmt();
      continue;
    }
    break;
  }
  return S;
}

bool isInc(const Stmt *S, Counter C) {
  S = unwrap(S);
  const auto *UO = dyn_cast_or_null<UnaryOperator>(S);
  return UO && UO->isIncrementOp() && refersToCounter(UO->getSubExpr(), C);
}

bool isDec(const Stmt *S, Counter C) {
  S = unwrap(S);
  const auto *UO = dyn_cast_or_null<UnaryOperator>(S);
  return UO && UO->isDecrementOp() && refersToCounter(UO->getSubExpr(), C);
}

bool isAssignZero(const Stmt *S, Counter C) {
  S = unwrap(S);
  const auto *BO = dyn_cast_or_null<BinaryOperator>(S);
  if (!BO || !BO->isAssignmentOp() || BO->getOpcode() != BO_Assign)
    return false;
  if (!refersToCounter(BO->getLHS(), C))
    return false;
  return isLiteralZero(BO->getRHS());
}

bool stmtHasResume(const Stmt *S, Counter C) {
  if (!S)
    return false;
  if (isDec(S, C) || isAssignZero(S, C))
    return true;
  for (const Stmt *Child : S->children()) {
    if (stmtHasResume(Child, C))
      return true;
  }
  return false;
}

class HoldWalker {
  UnbalancedHoldInterruptsCheck &Check;

public:
  explicit HoldWalker(UnbalancedHoldInterruptsCheck &Check) : Check(Check) {}

  RegionState walk(const Stmt *S, RegionState St, ResumeAfter Rest) {
    if (!S)
      return St;
    S = unwrap(S);
    if (!S)
      return St;

    if (const auto *CS = dyn_cast<CompoundStmt>(S)) {
      llvm::SmallVector<const Stmt *, 16> Body(CS->body_begin(),
                                               CS->body_end());
      for (size_t I = 0; I < Body.size(); ++I) {
        ResumeAfter Tail = Rest;
        for (size_t J = I + 1; J < Body.size(); ++J) {
          if (stmtHasResume(Body[J], Counter::Hold))
            Tail.Hold = true;
          if (stmtHasResume(Body[J], Counter::Cancel))
            Tail.Cancel = true;
        }
        St = walk(Body[I], St, Tail);
      }
      return St;
    }

    if (const auto *DS = dyn_cast<DoStmt>(S)) {
      const RegionState Inner = walk(DS->getBody(), St, Rest);
      // do { ... } while (0) is RESUME_INTERRUPTS / RESUME_CANCEL_INTERRUPTS.
      if (isLiteralZero(DS->getCond()))
        return Inner;
      return St;
    }

    if (const auto *IS = dyn_cast<IfStmt>(S)) {
      walk(IS->getCond(), St, Rest);
      walk(IS->getThen(), St, Rest);
      walk(IS->getElse(), St, Rest);
      return St;
    }

    if (const auto *SS = dyn_cast<SwitchStmt>(S)) {
      walk(SS->getCond(), St, Rest);
      walk(SS->getBody(), St, Rest);
      return St;
    }

    if (const auto *WS = dyn_cast<WhileStmt>(S)) {
      walk(WS->getCond(), St, Rest);
      walk(WS->getBody(), St, Rest);
      return St;
    }

    if (const auto *FS = dyn_cast<ForStmt>(S)) {
      walk(FS->getInit(), St, Rest);
      walk(FS->getCond(), St, Rest);
      walk(FS->getInc(), St, Rest);
      walk(FS->getBody(), St, Rest);
      return St;
    }

    if (const auto *CO = dyn_cast<ConditionalOperator>(S)) {
      walk(CO->getCond(), St, Rest);
      walk(CO->getTrueExpr(), St, Rest);
      walk(CO->getFalseExpr(), St, Rest);
      return St;
    }

    if (const auto *BO = dyn_cast<BinaryOperator>(S)) {
      if (BO->getOpcode() == BO_LAnd || BO->getOpcode() == BO_LOr) {
        walk(BO->getLHS(), St, Rest);
        walk(BO->getRHS(), St, Rest);
        return St;
      }
      if (BO->isAssignmentOp() && BO->getOpcode() == BO_Assign) {
        if (refersToCounter(BO->getLHS(), Counter::Hold) &&
            isLiteralZero(BO->getRHS()))
          St.Hold = 0;
        if (refersToCounter(BO->getLHS(), Counter::Cancel) &&
            isLiteralZero(BO->getRHS()))
          St.Cancel = 0;
        return St;
      }
    }

    if (const auto *SE = dyn_cast<StmtExpr>(S))
      return walk(SE->getSubStmt(), St, Rest);

    if (const auto *RS = dyn_cast<ReturnStmt>(S)) {
      if (const Expr *RV = RS->getRetValue())
        St = walk(RV, St, Rest);
      diagnoseReturn(RS, St, Rest);
      return St;
    }

    if (isInc(S, Counter::Hold)) {
      St.Hold++;
      return St;
    }
    if (isDec(S, Counter::Hold)) {
      if (St.Hold > 0)
        St.Hold--;
      return St;
    }
    if (isInc(S, Counter::Cancel)) {
      St.Cancel++;
      return St;
    }
    if (isDec(S, Counter::Cancel)) {
      if (St.Cancel > 0)
        St.Cancel--;
      return St;
    }

    for (const Stmt *Child : S->children())
      St = walk(Child, St, Rest);
    return St;
  }

private:
  void diagnoseReturn(const ReturnStmt *RS, const RegionState &St,
                      ResumeAfter Rest) {
    if (St.Hold > 0 && Rest.Hold) {
      Check.diag(RS->getBeginLoc(),
                 "HOLD_INTERRUPTS() without matching RESUME_INTERRUPTS() "
                 "on this path; leaked InterruptHoldoffCount blocks "
                 "CHECK_FOR_INTERRUPTS()");
    }
    if (St.Cancel > 0 && Rest.Cancel) {
      Check.diag(RS->getBeginLoc(),
                 "HOLD_CANCEL_INTERRUPTS() without matching "
                 "RESUME_CANCEL_INTERRUPTS() on this path; leaked "
                 "QueryCancelHoldoffCount blocks query cancel");
    }
  }
};

} // namespace

void UnbalancedHoldInterruptsCheck::registerMatchers(MatchFinder *Finder) {
  Finder->addMatcher(
      functionDecl(
          isDefinition(),
          hasDescendant(unaryOperator(
              anyOf(hasOperatorName("++"), hasOperatorName("--")),
              hasUnaryOperand(ignoringParenCasts(declRefExpr(to(varDecl(
                  hasAnyName("InterruptHoldoffCount",
                             "QueryCancelHoldoffCount")))))))))
          .bind("func"),
      this);
}

void UnbalancedHoldInterruptsCheck::check(
    const MatchFinder::MatchResult &Result) {
  const auto *FD = Result.Nodes.getNodeAs<FunctionDecl>("func");
  if (!FD || !FD->hasBody())
    return;
  HoldWalker(*this).walk(FD->getBody(), RegionState{}, ResumeAfter{});
}

} // namespace postgres
} // namespace tidy
} // namespace clang
