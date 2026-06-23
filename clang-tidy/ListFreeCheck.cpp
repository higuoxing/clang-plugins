#include "ListFreeCheck.h"
#include "clang/AST/ASTContext.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"

using namespace clang::ast_matchers;

namespace clang {
namespace tidy {
namespace postgres {

void ListFreeCheck::registerMatchers(MatchFinder *Finder) {
  // Match a call to pfree() where the argument is of type List *
  Finder->addMatcher(
      callExpr(
          callee(functionDecl(hasName("pfree"))),
          hasArgument(0, expr(hasType(pointsTo(
                             namedDecl(hasName("List"))))).bind("list_arg")))
          .bind("pfree_call"),
      this);
}

void ListFreeCheck::check(const MatchFinder::MatchResult &Result) {
  const auto *Call = Result.Nodes.getNodeAs<CallExpr>("pfree_call");
  const auto *Arg = Result.Nodes.getNodeAs<Expr>("list_arg");

  if (!Call || !Arg)
    return;

  // Actually, a better way to suppress is to check the enclosing function.
  // We can do this by finding the ancestor.
  auto Parents = Result.Context->getParents(*Call);
  while (!Parents.empty()) {
    const auto &Parent = Parents[0];
    if (const auto *FD = Parent.get<FunctionDecl>()) {
      if (FD->getNameAsString() == "list_free_private")
        return;
      break; // Found the enclosing function
    }
    Parents = Result.Context->getParents(Parent);
  }

  diag(Call->getBeginLoc(), "Applying pfree() on a list is not allowed. Use list_free() instead.")
      << Arg->getSourceRange();
}

} // namespace postgres
} // namespace tidy
} // namespace clang
