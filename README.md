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

4. TypedefMismatchCheck (clang-tidy):

   `pg-typedef-mismatch` flags call arguments that mix PostgreSQL typedefs whose underlying types convert silently but whose values are not interchangeable. Reported cliques:

   - `Buffer` / `BlockNumber` / `OffsetNumber` (buffer id vs page number vs item offset)
   - `AttrNumber` vs `Buffer` or `BlockNumber` (column number vs page/buffer)
   - `Oid` vs `TransactionId`

   Passing `stack->buffer` to `PredicateLockPage(..., BlockNumber, ...)` compiles without a warning and locks the wrong page.

   It does **not** warn about `BufferGetBlockNumber(buf)`, an explicit cast, or other integer typedefs that Postgres mixes on purpose (`uint32`/`BlockNumber`, `Timestamp`/`TimestampTz`, GIN's `AttrNumber` stored as `OffsetNumber`, `HeapTupleHeaderSetCmin(InvalidTransactionId)`).

   ```c
   PredicateLockPage(rel, stack->buffer, snap);                 // Unsafe: Buffer where BlockNumber is expected.
   PredicateLockPage(rel, BufferGetBlockNumber(stack->buffer), snap);  // OK.
   ```

5. UnsafeInCritSectionCheck (clang-tidy):

   `pg-unsafe-in-crit-section` flags operations that are illegal between `START_CRIT_SECTION()` / `END_CRIT_SECTION()`, or while a spinlock is held.

   In a critical section, `palloc()` / `repalloc()` / `MemoryContextAlloc()` (and the strdup/sprintf helpers) are forbidden: allocation failure is promoted to PANIC. `MemoryContextAlloc(ErrorContext, ...)` is allowed (`ErrorContext` is marked `allowInCritSection`). `elog(ERROR)` in a crit section is **not** flagged: core Postgres uses it as an invariant failure that should PANIC.

   While holding a spinlock, both allocations and `ereport`/`elog` at `ERROR` or `FATAL` are flagged: they can leave the lock stuck. `WARNING` and `PANIC` are left alone.

   The walk is intra-procedural. `do { ... } while (0)` statement macros (`END_CRIT_SECTION`, `PGSTAT_BEGIN_WRITE_ACTIVITY`) leak region depth to the caller; an `if` that starts a crit section on only one branch does not.

   ```c
   START_CRIT_SECTION();
   palloc(8);              // Unsafe: OOM becomes PANIC.
   END_CRIT_SECTION();

   SpinLockAcquire(&lock);
   palloc(8);              // Unsafe: ERROR would leave the lock stuck.
   SpinLockRelease(&lock);
   ```

6. ReturnInPgTryBlockCheck (clang-tidy):

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

7. MissingMemoryContextRestoreCheck (clang-tidy):

   `pg-missing-memory-context-restore` flags `PG_CATCH()` blocks that continue after an error without switching away from `ErrorContext`. `longjmp` lands in `ErrorContext`; without `MemoryContextSwitchTo()` (or `PG_RE_THROW()` / `ReThrowError()` / `ereport(ERROR)`), later `palloc`s and the caller's `CurrentMemoryContext` stay on `ErrorContext`.

   `PG_FINALLY()` is ignored. Same-translation-unit helpers that switch context, the usual PL `*subtrans_abort*` wrappers, and transaction abort/start helpers that restore context (`AbortOutOfAnyTransaction`, `AbortCurrentTransaction`, `StartTransactionCommand`, `RollbackAndReleaseCurrentSubTransaction`) are accepted. An assignment to `CurrentMemoryContext` counts as a restore.

   ```c
   PG_TRY();
   {
       ...
   }
   PG_CATCH();
   {
       FlushErrorState();  // Unsafe: still in ErrorContext.
   }
   PG_END_TRY();

   PG_CATCH();
   {
       MemoryContextSwitchTo(oldcontext);  // OK.
       FlushErrorState();
   }
   ```

8. UnbalancedHoldInterruptsCheck (clang-tidy):

   `pg-unbalanced-hold-interrupts` flags `HOLD_INTERRUPTS()` / `HOLD_CANCEL_INTERRUPTS()` that an early `return` skips past, so `RESUME_*` never runs on that path. A leaked `InterruptHoldoffCount` (or `QueryCancelHoldoffCount`) makes `CHECK_FOR_INTERRUPTS()` a no-op; cancel and die stay queued.

   The walk is intra-procedural, like `pg-unsafe-in-crit-section`. `do { ... } while (0)` (`RESUME_INTERRUPTS`) leaks depth; an `if` that HOLDs on one branch does not. Acquire-style helpers that HOLD and return still held (`LWLockAcquire`) have no later `RESUME` in the same function and are left alone.

   ```c
   HOLD_INTERRUPTS();
   if (failed)
       return;            // Unsafe: skips RESUME_INTERRUPTS.
   RESUME_INTERRUPTS();
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

Load the clang-tidy module (`pg-return-in-pg-try-block`, `pg-catch-missing-flush-or-rethrow`, `pg-missing-volatile-in-pg-try`, `pg-missing-memory-context-restore`, `pg-palloc-runtime-mul`, `pg-typedef-mismatch`, `pg-unsafe-in-crit-section`, and `pg-unbalanced-hold-interrupts`):

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

- MissingMemoryContextRestore:
  - https://www.postgresql.org/message-id/CANerzAd_S-yQ+L3e8hPp+as7eJWoTJ9sXw0jbV5AKTarrz0igg@mail.gmail.com
  - `src/backend/utils/adt/xml.c` (`wellformed_xml`: CATCH only `FlushErrorState()`, leaving `CurrentMemoryContext` as `ErrorContext`). Present in PostgreSQL 9.4 through 16; HEAD uses `ErrorSaveContext` instead of `PG_CATCH`.

- TypedefMismatch:
  - https://www.postgresql.org/message-id/20230803165638.nyjgdqxg7korp54r@erthalion.local
  - `src/backend/access/gin/ginget.c` (`PredicateLockPage(..., stack->buffer, ...)`: `Buffer` where `BlockNumber` is required). Present in PostgreSQL 11.0 and 14.0; HEAD uses `BufferGetBlockNumber(stack->buffer)`.

- UnsafeInCritSection:
  - https://www.postgresql.org/message-id/E1WW2LR-0007Kr-7O@gemulon.postgresql.org (assert against palloc in a critical section)
  - https://www.postgresql.org/message-id/E1jgWNs-0000JL-Qg@gemulon.postgresql.org (palloc while holding a spinlock)
  - `src/backend/postmaster/checkpointer.c` (`AbsorbFsyncRequests`: `palloc` inside `START_CRIT_SECTION()`). Present in PostgreSQL 9.4.0; 9.6+ allocates first, then enters the crit section so only the hashtable absorb panics on OOM.

- UnbalancedHoldInterrupts:
  - https://www.postgresql.org/message-id/19557-d88cb23f38eb9b91@postgresql.org (leaked `InterruptHoldoffCount` hangs a backend in ParallelFinish; cancel/die never run)
  - `src/backend/tcop/postgres.c` (`SocketBackend`: `HOLD_CANCEL_INTERRUPTS()` then `return` on client EOF without `RESUME_CANCEL_INTERRUPTS()`). Present in PostgreSQL 9.6 through HEAD; the caller then `proc_exit(0)`, so the leaked cancel holdoff does not outlive the backend.

- PallocRuntimeMul (examples in current PostgreSQL sources):
  - `src/fe_utils/astreamer_gzip.c` (`palloc(items * size)`)
  - `src/backend/utils/fmgr/funcapi.c` (`palloc(numargs * sizeof(...))`)

## License

These plugins are licensed under the MIT License. See the [LICENSE](./LICENSE) file for details.
