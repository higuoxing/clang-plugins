#ifndef LLVM_CLANG_TOOLS_EXTRA_CLANG_TIDY_POSTGRES_DISCARDEDLISTORBMSRESULTCHECK_H
#define LLVM_CLANG_TOOLS_EXTRA_CLANG_TIDY_POSTGRES_DISCARDEDLISTORBMSRESULTCHECK_H

#include "clang-tidy/ClangTidyCheck.h"

namespace clang {
namespace tidy {
namespace postgres {

/// Flags calls to List/Bitmapset functions that recycle their input
/// (lappend, bms_add_member, …) when the return value is discarded.
/// Those helpers may repalloc or replace the pointer; the caller must
/// write `list = lappend(list, x)` (or equivalent).
///
/// An explicit `(void)` cast is treated as a deliberate ignore.
class DiscardedListOrBmsResultCheck : public ClangTidyCheck {
public:
  DiscardedListOrBmsResultCheck(StringRef Name, ClangTidyContext *Context)
      : ClangTidyCheck(Name, Context) {}
  void registerMatchers(ast_matchers::MatchFinder *Finder) override;
  void check(const ast_matchers::MatchFinder::MatchResult &Result) override;
};

} // namespace postgres
} // namespace tidy
} // namespace clang

#endif // LLVM_CLANG_TOOLS_EXTRA_CLANG_TIDY_POSTGRES_DISCARDEDLISTORBMSRESULTCHECK_H
