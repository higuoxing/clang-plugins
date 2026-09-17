#include "MissingMemoryContextRestoreCheck.h"

#include "clang/AST/ASTContext.h"
#include "clang/AST/Expr.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"

using namespace clang::ast_matchers;

namespace clang {
namespace tidy {
namespace postgres {
namespace {

// Postgres elog.h: ERROR=21. errstart at ERROR or higher does not return.
constexpr int kErrorLevel = 21;

const BinaryOperator *asAssignment(const Stmt *S) {
  const auto *E = dyn_cast<Expr>(S);
  if (!E)
    return nullptr;
  const auto *BO = dyn_cast<BinaryOperator>(E->IgnoreParenImpCasts());
  if (!BO || !BO->isAssignmentOp())
    return nullptr;
  return BO;
}

bool isDoRethrowAssign(const Stmt *S) {
  if (const auto *CS = dyn_cast<CompoundStmt>(S)) {
    if (CS->size() != 1)
      return false;
    S = *CS->body_begin();
  }
  const BinaryOperator *BO = asAssignment(S);
  if (!BO)
    return false;
  const auto *DRE =
      dyn_cast<DeclRefExpr>(BO->getLHS()->IgnoreParenImpCasts());
  return DRE && DRE->getDecl()->getName().starts_with("_do_rethrow");
}

bool isRestoreName(StringRef Name) {
  if (Name == "MemoryContextSwitchTo")
    return true;
  // Abort/start wrappers leave ErrorContext: AbortOutOfAnyTransaction
  // switches to TopMemoryContext, StartTransactionCommand to
  // CurTransactionContext. Subxact abort restores priorContext.
  if (Name == "AbortOutOfAnyTransaction" ||
      Name == "AbortCurrentTransaction" ||
      Name == "StartTransactionCommand" ||
      Name == "RollbackAndReleaseCurrentSubTransaction")
    return true;
  // PL abort helpers switch to the caller's context, then CopyErrorData.
  return Name.contains("subtrans_abort") ||
         Name.contains("subtransaction_abort");
}

bool isRethrowName(StringRef Name) {
  return Name == "pg_re_throw" || Name == "ReThrowError";
}

bool isErrstartName(StringRef Name) {
  return Name == "errstart" || Name == "errstart_cold";
}

bool isThrowingErrorLevel(const Expr *E, ASTContext &Ctx) {
  if (!E)
    return false;
  E = E->IgnoreParenImpCasts();
  if (!E->isIntegerConstantExpr(Ctx))
    return false;
  Expr::EvalResult Ev;
  if (!E->EvaluateAsInt(Ev, Ctx, Expr::SE_AllowSideEffects))
    return false;
  return Ev.Val.getInt().getSExtValue() >= kErrorLevel;
}

bool isCurrentMemoryContextAssign(const BinaryOperator *BO) {
  if (!BO || !BO->isAssignmentOp())
    return false;
  const auto *DRE =
      dyn_cast<DeclRefExpr>(BO->getLHS()->IgnoreParenImpCasts());
  return DRE && DRE->getDecl()->getName() == "CurrentMemoryContext";
}

enum class CatchAction { None, Restore, Rethrow };

CatchAction mergeAction(CatchAction A, CatchAction B) {
  if (A == CatchAction::Restore || B == CatchAction::Restore)
    return CatchAction::Restore;
  if (A == CatchAction::Rethrow || B == CatchAction::Rethrow)
    return CatchAction::Rethrow;
  return CatchAction::None;
}

CatchAction stmtCatchAction(const Stmt *S, ASTContext &Ctx,
                            llvm::SmallPtrSet<const FunctionDecl *, 8> &Seen,
                            unsigned Depth);

class CatchActionVisitor : public RecursiveASTVisitor<CatchActionVisitor> {
  ASTContext &Ctx;
  CatchAction Action = CatchAction::None;

public:
  explicit CatchActionVisitor(ASTContext &Ctx) : Ctx(Ctx) {}

  CatchAction getAction() const { return Action; }

  bool VisitCallExpr(CallExpr *CE) {
    const FunctionDecl *FD = CE->getDirectCallee();
    if (!FD)
      return true;
    const StringRef Name = FD->getName();
    if (isRestoreName(Name))
      Action = mergeAction(Action, CatchAction::Restore);
    else if (isRethrowName(Name))
      Action = mergeAction(Action, CatchAction::Rethrow);
    else if (isErrstartName(Name) && CE->getNumArgs() > 0 &&
             isThrowingErrorLevel(CE->getArg(0), Ctx))
      Action = mergeAction(Action, CatchAction::Rethrow);
    return true;
  }

  bool VisitBinaryOperator(BinaryOperator *BO) {
    if (isCurrentMemoryContextAssign(BO))
      Action = mergeAction(Action, CatchAction::Restore);
    return true;
  }
};

CatchAction stmtCatchAction(const Stmt *S, ASTContext &Ctx,
                            llvm::SmallPtrSet<const FunctionDecl *, 8> &Seen,
                            unsigned Depth) {
  if (!S || Depth > 8)
    return CatchAction::None;

  CatchActionVisitor V(Ctx);
  V.TraverseStmt(const_cast<Stmt *>(S));
  CatchAction Action = V.getAction();
  if (Action != CatchAction::None)
    return Action;

  llvm::SmallVector<const Stmt *, 4> CalleeBodies;
  class CallCollector : public RecursiveASTVisitor<CallCollector> {
    llvm::SmallVector<const CallExpr *, 8> Calls;

  public:
    bool VisitCallExpr(CallExpr *CE) {
      Calls.push_back(CE);
      return true;
    }
    const llvm::SmallVector<const CallExpr *, 8> &calls() const {
      return Calls;
    }
  } Collector;
  Collector.TraverseStmt(const_cast<Stmt *>(S));

  for (const CallExpr *CE : Collector.calls()) {
    const FunctionDecl *FD = CE->getDirectCallee();
    if (!FD)
      continue;
    FD = FD->getCanonicalDecl();
    const FunctionDecl *Def = FD->getDefinition();
    if (!Def || !Def->hasBody() || !Seen.insert(Def).second)
      continue;
    CalleeBodies.push_back(Def->getBody());
  }
  for (const Stmt *Body : CalleeBodies) {
    Action = mergeAction(Action, stmtCatchAction(Body, Ctx, Seen, Depth + 1));
    if (Action != CatchAction::None)
      return Action;
  }
  return Action;
}

} // namespace

void MissingMemoryContextRestoreCheck::registerMatchers(MatchFinder *Finder) {
  Finder->addMatcher(
      ifStmt(hasCondition(binaryOperator(
                 hasOperatorName("=="),
                 hasOperands(callExpr(callee(functionDecl(hasName("__sigsetjmp")))),
                             integerLiteral(equals(0))))))
          .bind("pg_try"),
      this);
}

void MissingMemoryContextRestoreCheck::check(
    const MatchFinder::MatchResult &Result) {
  const auto *If = Result.Nodes.getNodeAs<IfStmt>("pg_try");
  if (!If)
    return;

  const Stmt *Else = If->getElse();
  if (!Else || isDoRethrowAssign(Else))
    return;

  llvm::SmallPtrSet<const FunctionDecl *, 8> Seen;
  if (stmtCatchAction(Else, *Result.Context, Seen, 0) != CatchAction::None)
    return;

  diag(Else->getBeginLoc(),
       "PG_CATCH continues without restoring memory context; "
       "call MemoryContextSwitchTo() before FlushErrorState() or "
       "PG_RE_THROW() so CurrentMemoryContext is not left as ErrorContext");
}

} // namespace postgres
} // namespace tidy
} // namespace clang
