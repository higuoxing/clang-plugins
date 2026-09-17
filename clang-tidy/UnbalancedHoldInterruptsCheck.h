#ifndef LLVM_CLANG_TOOLS_EXTRA_CLANG_TIDY_POSTGRES_UNBALANCEDHOLDINTERRUPTSCHECK_H
#define LLVM_CLANG_TOOLS_EXTRA_CLANG_TIDY_POSTGRES_UNBALANCEDHOLDINTERRUPTSCHECK_H

#include "clang-tidy/ClangTidyCheck.h"

namespace clang {
namespace tidy {
namespace postgres {

/// Flags HOLD_INTERRUPTS() / HOLD_CANCEL_INTERRUPTS() that are skipped
/// past by an early return, leaving InterruptHoldoffCount or
/// QueryCancelHoldoffCount raised. A leaked holdoff makes
/// CHECK_FOR_INTERRUPTS() a no-op, so cancel/die may never run.
///
/// Only early returns that skip a later RESUME_* in the same function
/// are reported. Functions that HOLD and return still held on purpose
/// (LWLockAcquire) have no later RESUME and are left alone. An if that
/// HOLDs on one branch does not leak depth.
class UnbalancedHoldInterruptsCheck : public ClangTidyCheck {
public:
  UnbalancedHoldInterruptsCheck(StringRef Name, ClangTidyContext *Context)
      : ClangTidyCheck(Name, Context) {}
  void registerMatchers(ast_matchers::MatchFinder *Finder) override;
  void check(const ast_matchers::MatchFinder::MatchResult &Result) override;
};

} // namespace postgres
} // namespace tidy
} // namespace clang

#endif // LLVM_CLANG_TOOLS_EXTRA_CLANG_TIDY_POSTGRES_UNBALANCEDHOLDINTERRUPTSCHECK_H
