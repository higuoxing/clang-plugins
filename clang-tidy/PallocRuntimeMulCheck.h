#ifndef LLVM_CLANG_TOOLS_EXTRA_CLANG_TIDY_POSTGRES_PALLOCRUNTIMEMULCHECK_H
#define LLVM_CLANG_TOOLS_EXTRA_CLANG_TIDY_POSTGRES_PALLOCRUNTIMEMULCHECK_H

#include "clang-tidy/ClangTidyCheck.h"

namespace clang {
namespace tidy {
namespace postgres {

/// Flags palloc/repalloc family calls whose size argument is computed with a
/// runtime multiplication instead of mul_size()/palloc_array().
class PallocRuntimeMulCheck : public ClangTidyCheck {
public:
  PallocRuntimeMulCheck(StringRef Name, ClangTidyContext *Context)
      : ClangTidyCheck(Name, Context) {}
  void registerMatchers(ast_matchers::MatchFinder *Finder) override;
  void check(const ast_matchers::MatchFinder::MatchResult &Result) override;
};

} // namespace postgres
} // namespace tidy
} // namespace clang

#endif // LLVM_CLANG_TOOLS_EXTRA_CLANG_TIDY_POSTGRES_PALLOCRUNTIMEMULCHECK_H
