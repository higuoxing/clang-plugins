# Clang Plugins Collection

> Collection of clang plugins that I wrote.

## Plugins

1. PallocRuntimeMulCheck (clang-tidy):

   `pg-palloc-runtime-mul` flags `palloc()` / `repalloc()` / `MemoryContextAlloc()` family calls whose size argument is a runtime multiplication (`n * sizeof(T)`, `n * m`, …) instead of an overflow-checked helper such as `mul_size()`, `palloc_mul()`, or `palloc_array()`. Integer overflow in the size computation can wrap and request a too-small buffer.

   It does **not** warn about compile-time products (`palloc(16 * 4)`), `palloc(mul_size(...))` / `palloc_array()`, or multiplying by 0 or 1 (`n * sizeof(char)`).

2. MissingVolatileInPgTryCheck (clang-tidy):

   `pg-missing-volatile-in-pg-try` flags automatic locals that are modified in `PG_TRY()` and then read in `PG_CATCH()` / `PG_FINALLY()` without being declared `volatile`. After `siglongjmp`, those values are indeterminate; GCC's `-Wclobbered` does not catch this reliably.

   CATCH/FINALLY analysis is flow-sensitive (Clang CFG). A use is flagged only if a clobbered value can reach it: reassignment on every path (`x = …; use(x)`, `for (j = 1; …; j++)`, both sides of an if/else) is fine, but `if (c) x = 1; use(x)` is not. Taking the address (`&x`) is not treated as a read.

   ```c
   int fd = open(...);
   PG_TRY();
   {
       ...
       close(fd);
       fd = -1;
   }
   PG_CATCH();
   {
       if (fd >= 0)   // fd must be volatile
           close(fd);
       PG_RE_THROW();
   }
   PG_END_TRY();
   ```

3. CatchMissingFlushOrRethrowCheck (clang-tidy):

   `pg-catch-missing-flush-or-rethrow` flags `PG_CATCH()` blocks that neither flush nor rethrow the caught error. Leaving CATCH without `FlushErrorState()`, `PG_RE_THROW()`, or `ReThrowError()` leaks an errordata stack slot (size 5); repeating that PANICs on a later `ereport()`. `ereport()` / `elog()` in CATCH is not a substitute: they push another slot.

   Same-translation-unit helpers that call those APIs are accepted, as are the usual PL `*subtrans_abort*` / `*subtransaction_abort*` wrappers. `PG_FINALLY()` is ignored (`PG_END_TRY()` rethrows).

   ```c
   PG_TRY();
   {
       ...
   }
   PG_CATCH();
   {
       ereport(ERROR, (errmsg("...")));  // Unsafe: flush or PG_RE_THROW first.
   }
   PG_END_TRY();
   ```

4. ReturnInPgTryBlockCheck (clang-tidy):

   `pg-return-in-pg-try-block` flags unsafe `return`/`continue`/`break`/`goto` statements in a `PG_TRY()` block. Those transfers break PostgreSQL's error stacks. E.g.,

   ```c
   label1:
   PG_TRY();
   {
   label2:
       return;       // Unsafe.
       break;        // Unsafe.
       continue;     // Unsafe.
       goto label1;  // Unsafe, because it's jumping out of PG_TRY block.
       for (;;)
       {
         break;
         continue;   // Safe. Will not warn about it.
       }
       goto label2;  // Safe. Will not warn about it.
   }
   PG_CATCH();
   ...
   PG_END_TRY();
   ```

## Build

To use these plugins, you'll need to have the latest stable LLVM (e.g., LLVM 21) installed on your system. You can download LLVM from the official website [](https://llvm.org/releases/) or install it through your package manager.

Once you have LLVM installed, you can build the plugins by running the following commands:

```bash
git clone git@github.com:higuoxing/clang-plugins.git
cd clang-plugins
mkdir build
cd build
cmake -DCT_CLANG_INSTALL_DIR=/<path>/<to>/<clang-install-dir>
make -j`nproc`
make test
```

## Usage

Load the clang-tidy module (`pg-return-in-pg-try-block`, `pg-catch-missing-flush-or-rethrow`, `pg-missing-volatile-in-pg-try`, and `pg-palloc-runtime-mul`):

```bash
clang-tidy -load=<path>/<to>/clang-plugins/build/lib/libPostgresTidyModule.dylib \
  -checks='-*,pg-*' \
  <your-source-file.c> -- <compiler-flags>
```

## Found issues:

- ReturnInPgTryBlock:
  - https://www.postgresql.org/message-id/CACpMh+CMsGMRKFzFMm3bYTzQmMU5nfEEoEDU2apJcc4hid36AQ@mail.gmail.com

- MissingVolatileInPgTry:
  - https://www.postgresql.org/message-id/13955.1422212567@sss.pgh.pa.us
  - https://github.com/citusdata/citus/commit/ada3ba25072cc5be055b3bbdedfa2fe936443b0d

- CatchMissingFlushOrRethrow:
  - https://www.postgresql.org/message-id/CAMEv5_v5Y+-D=CO1+qoe16sAmgC4sbbQjz+UtcHmB6zcgS+5Ew@mail.gmail.com
  - `contrib/jsonb_plpython/jsonb_plpython.c` (`PLyNumber_ToJsonbValue`: CATCH only `ereport(ERROR)`)

- PallocRuntimeMul (examples in current PostgreSQL sources):
  - `src/fe_utils/astreamer_gzip.c` (`palloc(items * size)`)
  - `src/backend/utils/fmgr/funcapi.c` (`palloc(numargs * sizeof(...))`)

## License

These plugins are licensed under the MIT License. See the [LICENSE](./LICENSE) file for details.
