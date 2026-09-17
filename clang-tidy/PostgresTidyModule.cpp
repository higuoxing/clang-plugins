#include "clang-tidy/ClangTidyModule.h"
#include "clang-tidy/ClangTidyModuleRegistry.h"
#include "CatchMissingFlushOrRethrowCheck.h"
#include "MissingMemoryContextRestoreCheck.h"
#include "MissingVolatileInPgTryCheck.h"
#include "PallocRuntimeMulCheck.h"
#include "ReturnInPgTryBlockCheck.h"
#include "TypedefMismatchCheck.h"
#include "UnsafeInCritSectionCheck.h"

namespace clang {
namespace tidy {
namespace postgres {

class PostgresModule : public ClangTidyModule {
public:
  void addCheckFactories(ClangTidyCheckFactories &CheckFactories) override {
    CheckFactories.registerCheck<CatchMissingFlushOrRethrowCheck>(
        "pg-catch-missing-flush-or-rethrow");
    CheckFactories.registerCheck<MissingMemoryContextRestoreCheck>(
        "pg-missing-memory-context-restore");
    CheckFactories.registerCheck<MissingVolatileInPgTryCheck>(
        "pg-missing-volatile-in-pg-try");
    CheckFactories.registerCheck<PallocRuntimeMulCheck>(
        "pg-palloc-runtime-mul");
    CheckFactories.registerCheck<ReturnInPgTryBlockCheck>(
        "pg-return-in-pg-try-block");
    CheckFactories.registerCheck<TypedefMismatchCheck>(
        "pg-typedef-mismatch");
    CheckFactories.registerCheck<UnsafeInCritSectionCheck>(
        "pg-unsafe-in-crit-section");
  }
};

} // namespace postgres

// Register the PostgresTidyModule using this statically initialized variable.
static ClangTidyModuleRegistry::Add<postgres::PostgresModule>
    X("postgres-module", "Adds PostgreSQL specific checks.");

// This anchor is used to force the linker to link in the generated object file
// and thus register the PostgresModule.
volatile int PostgresModuleAnchorSource = 0;

} // namespace tidy
} // namespace clang
