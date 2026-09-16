# Clang Plugins Collection

> Collection of clang plugins that I wrote.

## Plugins

1. PallocRuntimeMulCheck (clang-tidy):

   `pg-palloc-runtime-mul` flags `palloc()` / `repalloc()` / `MemoryContextAlloc()` family calls whose size argument is a runtime multiplication (`n * sizeof(T)`, `n * m`, …) instead of an overflow-checked helper such as `mul_size()`, `palloc_mul()`, or `palloc_array()`. Integer overflow in the size computation can wrap and request a too-small buffer.

   It does **not** warn about compile-time products (`palloc(16 * 4)`), `palloc(mul_size(...))` / `palloc_array()`, or multiplying by 0 or 1 (`n * sizeof(char)`).

2. ReturnInPgTryBlockCheck (clang-tidy):

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

Load the clang-tidy module (`pg-return-in-pg-try-block` and `pg-palloc-runtime-mul`):

```bash
clang-tidy -load=<path>/<to>/clang-plugins/build/lib/libPostgresTidyModule.dylib \
  -checks='-*,pg-*' \
  <your-source-file.c> -- <compiler-flags>
```

## Found issues:

- ReturnInPgTryBlock:
  - https://www.postgresql.org/message-id/CACpMh+CMsGMRKFzFMm3bYTzQmMU5nfEEoEDU2apJcc4hid36AQ@mail.gmail.com

- PallocRuntimeMul (examples in current PostgreSQL sources):
  - `src/fe_utils/astreamer_gzip.c` (`palloc(items * size)`)
  - `src/backend/utils/fmgr/funcapi.c` (`palloc(numargs * sizeof(...))`)

## License

These plugins are licensed under the MIT License. See the [LICENSE](./LICENSE) file for details.
