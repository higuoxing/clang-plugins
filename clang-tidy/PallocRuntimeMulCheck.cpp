#include "PallocRuntimeMulCheck.h"

#include "clang/AST/ASTContext.h"
#include "clang/AST/Expr.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/Basic/DiagnosticIDs.h"
#include "llvm/ADT/StringSwitch.h"

using namespace clang::ast_matchers;

namespace clang {
namespace tidy {
namespace postgres {
namespace {

// Allocation functions whose size operands should be overflow-checked.
// Values are 0-based argument indexes of Size/size_t request sizes.
unsigned getSizeArgIndex(StringRef Name, unsigned &SecondSizeArg) {
  SecondSizeArg = ~0u;
  return llvm::StringSwitch<unsigned>(Name)
      .Cases("palloc", "palloc0", "palloc_extended", "palloc_aligned", 0u)
      .Cases("pg_malloc", "pg_malloc0", "pg_malloc_extended", 0u)
      .Case("SPI_palloc", 0u)
      .Cases("MemoryContextAlloc", "MemoryContextAllocZero",
             "MemoryContextAllocExtended", "MemoryContextAllocAligned",
             "MemoryContextAllocHuge", 1u)
      .Cases("repalloc", "repalloc_extended", "repalloc_huge", 1u)
      .Cases("pg_realloc", "SPI_repalloc", 1u)
      .Case("repalloc0", // oldsize at 1, new size at 2
            (SecondSizeArg = 2u, 1u))
      .Default(~0u);
}

bool isSafeAllocHelper(StringRef Name) {
  return llvm::StringSwitch<bool>(Name)
      .Cases("mul_size", "palloc_mul", "palloc0_mul", "palloc_mul_extended",
             true)
      .Cases("repalloc_mul", "repalloc_mul_extended", true)
      .Cases("pg_malloc_mul", "pg_malloc0_mul", "pg_malloc_mul_extended",
             "pg_realloc_mul", true)
      .Default(false);
}

const Expr *strip(const Expr *E) {
  return E ? E->IgnoreParenCasts() : nullptr;
}

bool isIntegerConstant(const Expr *E, ASTContext &Ctx) {
  E = strip(E);
  return E && E->isIntegerConstantExpr(Ctx);
}

// Multiplying by 0 or 1 cannot wrap to a smaller nonzero size.
bool isIgnorableConstantFactor(const Expr *E, ASTContext &Ctx) {
  E = strip(E);
  if (!E || !E->isIntegerConstantExpr(Ctx))
    return false;
  Expr::EvalResult Ev;
  if (!E->EvaluateAsInt(Ev, Ctx, Expr::SE_AllowSideEffects))
    return false;
  const llvm::APSInt &Val = Ev.Val.getInt();
  return Val.isZero() || Val.isOne();
}

// Find a '*' whose product is not a compile-time constant.  Do not walk into
// function calls: palloc(mul_size(n, sizeof(*p))) is already safe.
const BinaryOperator *findRuntimeMul(const Expr *E, ASTContext &Ctx,
                                     int Depth = 0) {
  if (!E || Depth > 8)
    return nullptr;
  E = strip(E);
  if (!E)
    return nullptr;

  if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
    if (BO->isMultiplicativeOp() && BO->getOpcode() == BO_Mul) {
      if (isIgnorableConstantFactor(BO->getLHS(), Ctx) ||
          isIgnorableConstantFactor(BO->getRHS(), Ctx)) {
        if (const BinaryOperator *Found =
                findRuntimeMul(BO->getLHS(), Ctx, Depth + 1))
          return Found;
        return findRuntimeMul(BO->getRHS(), Ctx, Depth + 1);
      }
      if (!isIntegerConstant(BO->getLHS(), Ctx) ||
          !isIntegerConstant(BO->getRHS(), Ctx))
        return BO;
    }
    if (const BinaryOperator *Found = findRuntimeMul(BO->getLHS(), Ctx, Depth + 1))
      return Found;
    return findRuntimeMul(BO->getRHS(), Ctx, Depth + 1);
  }

  if (const auto *UO = dyn_cast<UnaryOperator>(E))
    return findRuntimeMul(UO->getSubExpr(), Ctx, Depth + 1);

  if (const auto *CO = dyn_cast<ConditionalOperator>(E)) {
    if (const BinaryOperator *Found =
            findRuntimeMul(CO->getTrueExpr(), Ctx, Depth + 1))
      return Found;
    return findRuntimeMul(CO->getFalseExpr(), Ctx, Depth + 1);
  }

  // palloc(sz) where Size sz = n * sizeof(*p);
  if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
    const auto *VD = dyn_cast<VarDecl>(DRE->getDecl());
    if (VD && VD->isLocalVarDecl() && VD->hasInit())
      return findRuntimeMul(VD->getInit(), Ctx, Depth + 1);
  }

  return nullptr;
}

} // namespace

void PallocRuntimeMulCheck::registerMatchers(MatchFinder *Finder) {
  Finder->addMatcher(
      callExpr(
          callee(functionDecl(hasAnyName(
              "palloc", "palloc0", "palloc_extended", "palloc_aligned",
              "pg_malloc", "pg_malloc0", "pg_malloc_extended", "SPI_palloc",
              "MemoryContextAlloc", "MemoryContextAllocZero",
              "MemoryContextAllocExtended", "MemoryContextAllocAligned",
              "MemoryContextAllocHuge", "repalloc", "repalloc_extended",
              "repalloc_huge", "repalloc0", "pg_realloc", "SPI_repalloc"))))
          .bind("alloc_call"),
      this);
}

void PallocRuntimeMulCheck::check(const MatchFinder::MatchResult &Result) {
  const auto *Call = Result.Nodes.getNodeAs<CallExpr>("alloc_call");
  if (!Call)
    return;

  const FunctionDecl *Callee = Call->getDirectCallee();
  if (!Callee)
    return;

  const FunctionDecl *Enclosing = nullptr;
  auto Parents = Result.Context->getParents(*Call);
  while (!Parents.empty()) {
    if (const auto *FD = Parents[0].get<FunctionDecl>()) {
      Enclosing = FD;
      break;
    }
    if (const auto *S = Parents[0].get<Stmt>())
      Parents = Result.Context->getParents(*S);
    else if (const auto *D = Parents[0].get<Decl>())
      Parents = Result.Context->getParents(*D);
    else
      break;
  }
  if (Enclosing && isSafeAllocHelper(Enclosing->getName()))
    return;

  unsigned Second = ~0u;
  unsigned First = getSizeArgIndex(Callee->getName(), Second);
  if (First == ~0u)
    return;

  auto DiagnoseArg = [&](unsigned ArgIdx) {
    if (ArgIdx >= Call->getNumArgs())
      return;
    const Expr *SizeArg = Call->getArg(ArgIdx);
    const BinaryOperator *Mul =
        findRuntimeMul(SizeArg, *Result.Context);
    if (!Mul)
      return;

    diag(Call->getBeginLoc(),
         "allocation size multiplies a runtime value without overflow "
         "checking; use mul_size(), palloc_array(), or palloc_mul()")
        << SizeArg->getSourceRange();
    diag(Mul->getOperatorLoc(), "runtime multiplication here",
         DiagnosticIDs::Note);
  };

  DiagnoseArg(First);
  if (Second != ~0u)
    DiagnoseArg(Second);
}

} // namespace postgres
} // namespace tidy
} // namespace clang
