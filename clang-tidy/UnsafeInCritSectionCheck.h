#ifndef LLVM_CLANG_TOOLS_EXTRA_CLANG_TIDY_POSTGRES_UNSAFEINCRITSECTIONCHECK_H
#define LLVM_CLANG_TOOLS_EXTRA_CLANG_TIDY_POSTGRES_UNSAFEINCRITSECTIONCHECK_H

#include "clang-tidy/ClangTidyCheck.h"

namespace clang {
namespace tidy {
namespace postgres {

/// Flags operations that are illegal between START_CRIT_SECTION() and
/// END_CRIT_SECTION(), or while holding a spinlock.
///
/// In a critical section, palloc-family calls are forbidden: OOM is
/// promoted to PANIC. MemoryContextAlloc(ErrorContext, ...) is allowed
/// (ErrorContext is marked allowInCritSection). elog(ERROR) is not
/// flagged here; core Postgres uses it as an invariant failure that
/// should PANIC.
///
/// While holding a spinlock, both allocations and errstart() at ERROR
/// or FATAL are flagged: they can leave the lock stuck.
class UnsafeInCritSectionCheck : public ClangTidyCheck {
public:
  UnsafeInCritSectionCheck(StringRef Name, ClangTidyContext *Context)
      : ClangTidyCheck(Name, Context) {}
  void registerMatchers(ast_matchers::MatchFinder *Finder) override;
  void check(const ast_matchers::MatchFinder::MatchResult &Result) override;
};

} // namespace postgres
} // namespace tidy
} // namespace clang

#endif // LLVM_CLANG_TOOLS_EXTRA_CLANG_TIDY_POSTGRES_UNSAFEINCRITSECTIONCHECK_H
