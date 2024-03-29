# Clang Plugins Collection

> Collection of clang plugins that I wrote.

## Plugins

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

To use these plugins, you'll need to have LLVM 15 installed on your system. You can download LLVM from the official website [](https://llvm.org/releases/) or install it through your package manager.

Once you have LLVM installed, you can build the plugins by running the following commands:

```bash
git clone git@github.com:higuoxing/clang-plugins.git
cd clang-plugins
mkdir build
cd build
cmake -DCT_CLANG_INSTALL_DIR=/<path>/<to>/<clang-install-dir>
make -j`nproc`
```

## Usage

1. Integrate with `scan-build`

   ```bash
   scan-build \
     -load-plugin <path>/<to>/clang-plugins/build/lib/libReturnInPgTryBlockChecker.so -enable-checker alpha.postgres.ReturnInPgTryBlockChecker \
     -load-plugin <path>/<to>/clang-plugins/build/lib/libListFreeChecker.so -enable-checker alpha.postgres.ListFreeChecker \
     -o <path>/<to>/<scan-build-reports> \
     make -j`nproc`
   ```

## Found issues:

- ListFreeChecker:
  - https://github.com/greenplum-db/gpdb/pull/14723

- ReturnInPgTryBlock:
  - https://www.postgresql.org/message-id/CACpMh+CMsGMRKFzFMm3bYTzQmMU5nfEEoEDU2apJcc4hid36AQ@mail.gmail.com

## License

These plugins are licensed under the MIT License. See the [LICENSE](./LICENSE) file for details.
