#include "TypedefMismatchCheck.h"

#include "clang/AST/ASTContext.h"
#include "clang/AST/Type.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"

using namespace clang::ast_matchers;

namespace clang {
namespace tidy {
namespace postgres {
namespace {

// Typedefs that convert silently (int vs uint32) but name different
// quantities. Unlike a "any two typedefs differ" rule, only these
// pairs are reported: Postgres mixes many integer typedefs on purpose
// (Oid/RegProcedure, uint32/BlockNumber, ...).
bool isIncompatibleTypedefPair(StringRef A, StringRef B) {
  if (A.empty() || B.empty() || A == B)
    return false;
  return (A == "Buffer" && B == "BlockNumber") ||
         (A == "BlockNumber" && B == "Buffer");
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
    if (!isIncompatibleTypedefPair(ArgTy, ParamTy))
      continue;

    diag(Arg->getExprLoc(),
         "passing '%0' where '%1' is expected; Buffer is a buffer identifier, "
         "BlockNumber is a page number")
        << ArgTy << ParamTy;
  }
}

} // namespace postgres
} // namespace tidy
} // namespace clang
