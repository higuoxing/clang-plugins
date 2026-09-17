#ifndef LLVM_CLANG_TOOLS_EXTRA_CLANG_TIDY_POSTGRES_TYPEDEFMISMATCHCHECK_H
#define LLVM_CLANG_TOOLS_EXTRA_CLANG_TIDY_POSTGRES_TYPEDEFMISMATCHCHECK_H

#include "clang-tidy/ClangTidyCheck.h"

namespace clang {
namespace tidy {
namespace postgres {

/// Flags call arguments that mix PostgreSQL typedefs whose underlying
/// types convert silently but whose values are not interchangeable.
/// The first pair is Buffer (buffer id) vs BlockNumber (page number).
class TypedefMismatchCheck : public ClangTidyCheck {
public:
  TypedefMismatchCheck(StringRef Name, ClangTidyContext *Context)
      : ClangTidyCheck(Name, Context) {}
  void registerMatchers(ast_matchers::MatchFinder *Finder) override;
  void check(const ast_matchers::MatchFinder::MatchResult &Result) override;
};

} // namespace postgres
} // namespace tidy
} // namespace clang

#endif // LLVM_CLANG_TOOLS_EXTRA_CLANG_TIDY_POSTGRES_TYPEDEFMISMATCHCHECK_H
