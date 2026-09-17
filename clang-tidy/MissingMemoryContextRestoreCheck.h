#ifndef LLVM_CLANG_TOOLS_EXTRA_CLANG_TIDY_POSTGRES_MISSINGMEMORYCONTEXTRESTORECHECK_H
#define LLVM_CLANG_TOOLS_EXTRA_CLANG_TIDY_POSTGRES_MISSINGMEMORYCONTEXTRESTORECHECK_H

#include "clang-tidy/ClangTidyCheck.h"

namespace clang {
namespace tidy {
namespace postgres {

/// Flags PG_CATCH() blocks that continue after an error without switching
/// away from ErrorContext. longjmp lands in ErrorContext; if CATCH
/// neither MemoryContextSwitchTo()s nor rethrows, later pallocs and the
/// caller's CurrentMemoryContext stay on ErrorContext.
///
/// PG_RE_THROW()/ReThrowError()/ereport(ERROR) are OK: abort resets
/// contexts. AbortOutOfAnyTransaction/StartTransactionCommand and the
/// usual PL *subtrans_abort* helpers also restore context. PG_FINALLY
/// is ignored.
class MissingMemoryContextRestoreCheck : public ClangTidyCheck {
public:
  MissingMemoryContextRestoreCheck(StringRef Name, ClangTidyContext *Context)
      : ClangTidyCheck(Name, Context) {}
  void registerMatchers(ast_matchers::MatchFinder *Finder) override;
  void check(const ast_matchers::MatchFinder::MatchResult &Result) override;
};

} // namespace postgres
} // namespace tidy
} // namespace clang

#endif // LLVM_CLANG_TOOLS_EXTRA_CLANG_TIDY_POSTGRES_MISSINGMEMORYCONTEXTRESTORECHECK_H
