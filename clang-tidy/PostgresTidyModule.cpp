#include "clang-tidy/ClangTidyModule.h"
#include "clang-tidy/ClangTidyModuleRegistry.h"
#include "MissingVolatileInPgTryCheck.h"
#include "PallocRuntimeMulCheck.h"
#include "ReturnInPgTryBlockCheck.h"

namespace clang {
namespace tidy {
namespace postgres {

class PostgresModule : public ClangTidyModule {
public:
  void addCheckFactories(ClangTidyCheckFactories &CheckFactories) override {
    CheckFactories.registerCheck<MissingVolatileInPgTryCheck>(
        "pg-missing-volatile-in-pg-try");
    CheckFactories.registerCheck<PallocRuntimeMulCheck>(
        "pg-palloc-runtime-mul");
    CheckFactories.registerCheck<ReturnInPgTryBlockCheck>(
        "pg-return-in-pg-try-block");
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
