#include "TypedefMismatchCheck.h"

#include "clang/AST/ASTContext.h"
#include "clang/AST/Type.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "llvm/ADT/ArrayRef.h"

using namespace clang::ast_matchers;

namespace clang {
namespace tidy {
namespace postgres {
namespace {

// Typedefs that convert silently but name different quantities.
// Only names that share a clique are reported. Postgres mixes many
// integer typedefs on purpose; a HEAD scan dropped:
//   Timestamp/TimestampTz (dozens of intentional conversions),
//   AttrNumber/OffsetNumber (GIN stores attnum as OffsetNumber),
//   CommandId/TransactionId (HeapTupleHeaderSetCmin(InvalidTransactionId)).
struct TypedefClique {
  llvm::ArrayRef<const char *const> Names;
  const char *Hint;
};

const char *const kPageLoc[] = {"Buffer", "BlockNumber", "OffsetNumber"};
const char *const kAttrLoc[] = {"AttrNumber", "Buffer", "BlockNumber"};
const char *const kOidXid[] = {"Oid", "TransactionId"};

const TypedefClique kCliques[] = {
    {kPageLoc, "these identify different page/item locations"},
    {kAttrLoc, "an attribute number is not a buffer or page number"},
    {kOidXid, "an object id is not a transaction id"},
};

const char *incompatibleHint(StringRef A, StringRef B) {
  if (A.empty() || B.empty() || A == B)
    return nullptr;
  for (const TypedefClique &C : kCliques) {
    bool HasA = false;
    bool HasB = false;
    for (const char *N : C.Names) {
      HasA |= A == N;
      HasB |= B == N;
    }
    if (HasA && HasB)
      return C.Hint;
  }
  return nullptr;
}

// Typedef as written, not the canonical integer. Do not look through
// pointers: Buffer* vs BlockNumber* is out of scope.
StringRef typedefName(QualType T) {
  if (T.isNull())
    return {};
  T = T.getUnqualifiedType();
  if (const auto *TT = T->getAs<TypedefType>())
    return TT->getDecl()->getName();
  return {};
}

} // namespace

void TypedefMismatchCheck::registerMatchers(MatchFinder *Finder) {
  Finder->addMatcher(callExpr(callee(functionDecl())).bind("call"), this);
}

void TypedefMismatchCheck::check(const MatchFinder::MatchResult &Result) {
  const auto *Call = Result.Nodes.getNodeAs<CallExpr>("call");
  if (!Call)
    return;

  const FunctionDecl *FD = Call->getDirectCallee();
  if (!FD || !FD->hasPrototype())
    return;

  const unsigned N =
      std::min(Call->getNumArgs(), static_cast<unsigned>(FD->getNumParams()));
  for (unsigned I = 0; I < N; ++I) {
    const StringRef ParamTy =
        typedefName(FD->getParamDecl(I)->getType());
    const Expr *Arg = Call->getArg(I);
    if (!Arg)
      continue;
    // Implicit integral conversions hide the source typedef (Buffer
    // becomes BlockNumber at the call). Explicit casts are left in
    // place so (BlockNumber)buf is treated as intentional.
    const StringRef ArgTy =
        typedefName(Arg->IgnoreParenImpCasts()->getType());
    const char *Hint = incompatibleHint(ArgTy, ParamTy);
    if (!Hint)
      continue;

    diag(Arg->getExprLoc(), "passing '%0' where '%1' is expected; %2")
        << ArgTy << ParamTy << Hint;
  }
}

} // namespace postgres
} // namespace tidy
} // namespace clang
