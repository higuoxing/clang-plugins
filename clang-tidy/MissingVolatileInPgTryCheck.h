#ifndef LLVM_CLANG_TOOLS_EXTRA_CLANG_TIDY_POSTGRES_MISSINGVOLATILEINPGTRYCHECK_H
#define LLVM_CLANG_TOOLS_EXTRA_CLANG_TIDY_POSTGRES_MISSINGVOLATILEINPGTRYCHECK_H

#include "clang-tidy/ClangTidyCheck.h"

namespace clang {
namespace tidy {
namespace postgres {

/// Flags automatic locals modified in PG_TRY() and read in PG_CATCH() /
/// PG_FINALLY() without a volatile qualifier. After siglongjmp their values
/// are indeterminate unless they are volatile.
class MissingVolatileInPgTryCheck : public ClangTidyCheck {
public:
  MissingVolatileInPgTryCheck(StringRef Name, ClangTidyContext *Context)
      : ClangTidyCheck(Name, Context) {}
  void registerMatchers(ast_matchers::MatchFinder *Finder) override;
  void check(const ast_matchers::MatchFinder::MatchResult &Result) override;
};

} // namespace postgres
} // namespace tidy
} // namespace clang

#endif // LLVM_CLANG_TOOLS_EXTRA_CLANG_TIDY_POSTGRES_MISSINGVOLATILEINPGTRYCHECK_H
