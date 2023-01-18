# clang-plugins
Collection of clang plugins that I wrote.

## Contents

1. ListFreeChecker (Path sensitive checker):

   `ListFreeChecker` is used to check if we're freeing a `List *` object with `pfree()` in projects based on Postgres. Since in Postgres 13+, `List` is implemented in array, it makes non-sense to free a list header.

2. ReturnInPgTryBlockChecker (Path insensitive checker based on AST-matcher):

   `ReturnInPgTryBlockChecker` is used to check if there are unsafe `return`/`continue`/`break`/`goto` statements in `PG_TRY()` block in projects based on Postgres. It will break PostgreSQL's error stacks. E.g.,

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

```bash
git clone git@github.com:higuoxing/clang-plugins.git
cd clang-plugins
mkdir build
cd build
cmake -DCT_CLANG_INSTALL_DIR=/<path>/<to>/<clang-install-dir>
make -j`nproc`
```

## Run

1. Integrate with `scan-build`

   ```bash
   scan-build \
     -load-plugin <path>/<to>/clang-plugins/build/lib/libReturnInPgTryBlockChecker.so -enable-checker alpha.postgres.ReturnInPgTryBlockChecker \
     -load-plugin <path>/<to>/clang-plugins/build/lib/libListFreeChecker.so -enable-checker alpha.postgres.ListFreeChecker \
     -o <path>/<to>/<scan-build-reports> \
     make -j`nproc`
   ```
