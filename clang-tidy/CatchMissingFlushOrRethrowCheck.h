#ifndef LLVM_CLANG_TOOLS_EXTRA_CLANG_TIDY_POSTGRES_CATCHMISSINGFLUSHORRETHROWCHECK_H
#define LLVM_CLANG_TOOLS_EXTRA_CLANG_TIDY_POSTGRES_CATCHMISSINGFLUSHORRETHROWCHECK_H

#include "clang-tidy/ClangTidyCheck.h"

namespace clang {
namespace tidy {
namespace postgres {

/// Flags PG_CATCH() blocks that neither flush nor rethrow the caught error.
/// Leaving CATCH without FlushErrorState(), PG_RE_THROW(), or ReThrowError()
/// leaks an errordata stack slot (depth 5) and can PANIC on later ereport().
/// ereport()/elog() in CATCH is not a substitute: they push another slot.
class CatchMissingFlushOrRethrowCheck : public ClangTidyCheck {
public:
  CatchMissingFlushOrRethrowCheck(StringRef Name, ClangTidyContext *Context)
      : ClangTidyCheck(Name, Context) {}
  void registerMatchers(ast_matchers::MatchFinder *Finder) override;
  void check(const ast_matchers::MatchFinder::MatchResult &Result) override;
};

} // namespace postgres
} // namespace tidy
} // namespace clang

#endif // LLVM_CLANG_TOOLS_EXTRA_CLANG_TIDY_POSTGRES_CATCHMISSINGFLUSHORRETHROWCHECK_H
