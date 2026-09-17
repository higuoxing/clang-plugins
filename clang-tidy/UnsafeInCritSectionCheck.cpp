#include "UnsafeInCritSectionCheck.h"

#include "clang/AST/ASTContext.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "llvm/ADT/StringSwitch.h"

using namespace clang::ast_matchers;

namespace clang {
namespace tidy {
namespace postgres {
namespace {

// Postgres elog.h: ERROR=21, FATAL=22, FATAL_CLIENT_ONLY=23, PANIC=24.
constexpr int kErrorLevel = 21;
constexpr int kPanicLevel = 24;

struct RegionState {
  int Crit = 0;
  int Spin = 0;

  bool inCrit() const { return Crit > 0; }
  bool inSpin() const { return Spin > 0; }
  bool inUnsafeRegion() const { return inCrit() || inSpin(); }
};

bool isLiteralZero(const Expr *E) {
  if (!E)
    return false;
  E = E->IgnoreParenImpCasts();
  if (const auto *IL = dyn_cast<IntegerLiteral>(E))
    return IL->getValue().isZero();
  return false;
}

bool refersToCritSectionCount(const Expr *E) {
  if (!E)
    return false;
  const auto *DRE = dyn_cast<DeclRefExpr>(E->IgnoreParenImpCasts());
  return DRE && DRE->getDecl()->getName() == "CritSectionCount";
}

bool isCritInc(const Stmt *S) {
  const auto *UO = dyn_cast<UnaryOperator>(S);
  return UO && UO->isIncrementOp() &&
         refersToCritSectionCount(UO->getSubExpr());
}

bool isCritDec(const Stmt *S) {
  const auto *UO = dyn_cast<UnaryOperator>(S);
  return UO && UO->isDecrementOp() &&
         refersToCritSectionCount(UO->getSubExpr());
}

StringRef calleeName(const CallExpr *CE) {
  const FunctionDecl *FD = CE->getDirectCallee();
  return FD ? FD->getName() : StringRef();
}

// Track the SpinLock* wrappers, not s_lock/s_unlock. S_LOCK expands
// to (TAS(lock) ? s_lock(...) : 0); treating s_lock as acquire would
// leak a fake held lock when both ternary arms are walked.
bool isSpinAcquireName(StringRef Name) { return Name == "SpinLockAcquire"; }

bool isSpinReleaseName(StringRef Name) { return Name == "SpinLockRelease"; }

// Backend allocators that AssertNotInCriticalSection, plus the
// overflow-checked wrappers and strdup/sprintf helpers that call them.
bool isAllocName(StringRef Name) {
  return llvm::StringSwitch<bool>(Name)
      .Cases("palloc", "palloc0", "palloc_extended", "palloc_aligned", true)
      .Cases("palloc_mul", "palloc0_mul", "palloc_mul_extended", true)
      .Cases("MemoryContextAlloc", "MemoryContextAllocZero",
             "MemoryContextAllocExtended", "MemoryContextAllocAligned",
             "MemoryContextAllocHuge", "MemoryContextStrdup", true)
      .Cases("repalloc", "repalloc_extended", "repalloc0", "repalloc_huge",
             "repalloc_mul", "repalloc_mul_extended", true)
      .Cases("pstrdup", "pnstrdup", "pchomp", "psprintf", true)
      .Cases("SPI_palloc", "SPI_repalloc", "SPI_pstrdup", true)
      .Cases("pg_malloc", "pg_malloc0", "pg_malloc_extended", "pg_realloc",
             true)
      .Default(false);
}

bool isContextAllocName(StringRef Name) {
  return llvm::StringSwitch<bool>(Name)
      .Cases("MemoryContextAlloc", "MemoryContextAllocZero",
             "MemoryContextAllocExtended", "MemoryContextAllocAligned",
             "MemoryContextAllocHuge", "MemoryContextStrdup", true)
      .Default(false);
}

bool isErrorContextArg(const Expr *E) {
  if (!E)
    return false;
  const auto *DRE = dyn_cast<DeclRefExpr>(E->IgnoreParenImpCasts());
  return DRE && DRE->getDecl()->getName() == "ErrorContext";
}

bool isErrstartName(StringRef Name) {
  return Name == "errstart" || Name == "errstart_cold";
}

// ERROR/FATAL become PANIC in a crit section; PANIC is already terminal.
bool isThrowingErrorLevel(const Expr *E, ASTContext &Ctx) {
  if (!E)
    return false;
  E = E->IgnoreParenImpCasts();
  if (!E->isIntegerConstantExpr(Ctx))
    return false;
  Expr::EvalResult Ev;
  if (!E->EvaluateAsInt(Ev, Ctx, Expr::SE_AllowSideEffects))
    return false;
  const int64_t V = Ev.Val.getInt().getSExtValue();
  return V >= kErrorLevel && V < kPanicLevel;
}

const Stmt *unwrap(const Stmt *S) {
  while (S) {
    if (const auto *E = dyn_cast<Expr>(S))
      S = E->IgnoreParenImpCasts();
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

class CritSectionWalker {
  UnsafeInCritSectionCheck &Check;
  ASTContext &Ctx;

public:
  CritSectionWalker(UnsafeInCritSectionCheck &Check, ASTContext &Ctx)
      : Check(Check), Ctx(Ctx) {}

  RegionState walk(const Stmt *S, RegionState St) {
    if (!S)
      return St;
    S = unwrap(S);
    if (!S)
      return St;

    if (const auto *CS = dyn_cast<CompoundStmt>(S)) {
      for (const Stmt *Child : CS->body())
        St = walk(Child, St);
      return St;
    }

    if (const auto *DS = dyn_cast<DoStmt>(S)) {
      const RegionState Inner = walk(DS->getBody(), St);
      // do { ... } while (0) is the usual statement-macro wrapper
      // (END_CRIT_SECTION, PGSTAT_BEGIN_WRITE_ACTIVITY). Depth changes
      // must leak to the surrounding block.
      if (isLiteralZero(DS->getCond()))
        return Inner;
      return St;
    }

    if (const auto *IS = dyn_cast<IfStmt>(S)) {
      walk(IS->getCond(), St);
      walk(IS->getThen(), St);
      walk(IS->getElse(), St);
      return St;
    }

    if (const auto *SS = dyn_cast<SwitchStmt>(S)) {
      walk(SS->getCond(), St);
      walk(SS->getBody(), St);
      return St;
    }

    if (const auto *WS = dyn_cast<WhileStmt>(S)) {
      walk(WS->getCond(), St);
      walk(WS->getBody(), St);
      return St;
    }

    if (const auto *FS = dyn_cast<ForStmt>(S)) {
      walk(FS->getInit(), St);
      walk(FS->getCond(), St);
      walk(FS->getInc(), St);
      walk(FS->getBody(), St);
      return St;
    }

    if (const auto *CO = dyn_cast<ConditionalOperator>(S)) {
      walk(CO->getCond(), St);
      walk(CO->getTrueExpr(), St);
      walk(CO->getFalseExpr(), St);
      return St;
    }

    if (const auto *BO = dyn_cast<BinaryOperator>(S)) {
      if (BO->getOpcode() == BO_LAnd || BO->getOpcode() == BO_LOr) {
        walk(BO->getLHS(), St);
        walk(BO->getRHS(), St);
        return St;
      }
    }

    if (const auto *SE = dyn_cast<StmtExpr>(S))
      return walk(SE->getSubStmt(), St);

    if (isCritInc(S)) {
      St.Crit++;
      return St;
    }
    if (isCritDec(S)) {
      if (St.Crit > 0)
        St.Crit--;
      return St;
    }

    if (const auto *CE = dyn_cast<CallExpr>(S))
      return walkCall(CE, St);

    for (const Stmt *Child : S->children())
      St = walk(Child, St);
    return St;
  }

private:
  RegionState walkCall(const CallExpr *CE, RegionState St) {
    const StringRef Name = calleeName(CE);

    if (isSpinAcquireName(Name)) {
      for (const Expr *Arg : CE->arguments())
        St = walk(Arg, St);
      St.Spin++;
      return St;
    }
    if (isSpinReleaseName(Name)) {
      if (St.Spin > 0)
        St.Spin--;
      for (const Expr *Arg : CE->arguments())
        St = walk(Arg, St);
      return St;
    }

    if (St.inUnsafeRegion() && isAllocName(Name)) {
      if (!(isContextAllocName(Name) && CE->getNumArgs() > 0 &&
            isErrorContextArg(CE->getArg(0)))) {
        diagnoseAlloc(CE, Name, St);
      }
    }

    if (St.inSpin() && isErrstartName(Name) && CE->getNumArgs() > 0 &&
        isThrowingErrorLevel(CE->getArg(0), Ctx)) {
      Check.diag(CE->getBeginLoc(),
                 "ereport/elog at ERROR or FATAL while holding a spinlock; "
                 "the lock would stay acquired");
    }

    for (const Stmt *Child : CE->children())
      St = walk(Child, St);
    return St;
  }

  void diagnoseAlloc(const CallExpr *CE, StringRef Name,
                     const RegionState &St) {
    if (St.inCrit()) {
      Check.diag(CE->getBeginLoc(),
                 "allocation with '%0' in a critical section; "
                 "OOM is promoted to PANIC")
          << Name;
      return;
    }
    Check.diag(CE->getBeginLoc(),
               "allocation with '%0' while holding a spinlock; "
               "it can elog(ERROR) and leave the lock stuck")
        << Name;
  }
};

} // namespace

void UnsafeInCritSectionCheck::registerMatchers(MatchFinder *Finder) {
  Finder->addMatcher(
      functionDecl(
          isDefinition(),
          anyOf(hasDescendant(unaryOperator(
                    anyOf(hasOperatorName("++"), hasOperatorName("--")),
                    hasUnaryOperand(ignoringParenImpCasts(declRefExpr(
                        to(varDecl(hasName("CritSectionCount")))))))),
                hasDescendant(callExpr(callee(functionDecl(hasAnyName(
                    "SpinLockAcquire", "SpinLockRelease")))))))
          .bind("func"),
      this);
}

void UnsafeInCritSectionCheck::check(const MatchFinder::MatchResult &Result) {
  const auto *FD = Result.Nodes.getNodeAs<FunctionDecl>("func");
  if (!FD || !FD->hasBody())
    return;
  CritSectionWalker(*this, *Result.Context)
      .walk(FD->getBody(), RegionState{});
}

} // namespace postgres
} // namespace tidy
} // namespace clang
