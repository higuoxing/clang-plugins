volatile unsigned CritSectionCount;

#define START_CRIT_SECTION() (CritSectionCount++)
#define END_CRIT_SECTION()                                                     \
  do {                                                                         \
    CritSectionCount--;                                                        \
  } while (0)

#define PGSTAT_BEGIN_WRITE_ACTIVITY(beentry)                                   \
  do {                                                                         \
    START_CRIT_SECTION();                                                      \
    (beentry)++;                                                               \
  } while (0)

#define PGSTAT_END_WRITE_ACTIVITY(beentry)                                     \
  do {                                                                         \
    (beentry)++;                                                               \
    END_CRIT_SECTION();                                                        \
  } while (0)

#define ERROR 21
#define WARNING 19
#define FATAL 22
#define PANIC 24

void *palloc(unsigned);
void *pstrdup(const char *);
void *MemoryContextAlloc(void *context, unsigned size);
void *ErrorContext;
int errstart(int elevel, const char *domain);
void SpinLockAcquire(void *lock);
void SpinLockRelease(void *lock);

void warn_palloc_in_crit(void) {
  START_CRIT_SECTION();
  palloc(8);
  // TIDY: :[[@LINE-1]]:3: warning: allocation with 'palloc' in a critical section; OOM is promoted to PANIC [pg-unsafe-in-crit-section]
  END_CRIT_SECTION();
}

void warn_pstrdup_in_if(int c) {
  START_CRIT_SECTION();
  if (c)
    pstrdup("x");
  // TIDY: :[[@LINE-1]]:5: warning: allocation with 'pstrdup' in a critical section
  END_CRIT_SECTION();
}

void warn_memory_context(void *ctx) {
  START_CRIT_SECTION();
  MemoryContextAlloc(ctx, 8);
  // TIDY: :[[@LINE-1]]:3: warning: allocation with 'MemoryContextAlloc' in a critical section
  END_CRIT_SECTION();
}

void warn_pgstat_wrapper(int beentry) {
  PGSTAT_BEGIN_WRITE_ACTIVITY(beentry);
  palloc(8);
  // TIDY: :[[@LINE-1]]:3: warning: allocation with 'palloc' in a critical section
  PGSTAT_END_WRITE_ACTIVITY(beentry);
}

void warn_palloc_under_spinlock(void *lock) {
  SpinLockAcquire(lock);
  palloc(8);
  // TIDY: :[[@LINE-1]]:3: warning: allocation with 'palloc' while holding a spinlock; it can elog(ERROR) and leave the lock stuck [pg-unsafe-in-crit-section]
  SpinLockRelease(lock);
}

void warn_errstart_under_spinlock(void *lock) {
  SpinLockAcquire(lock);
  errstart(ERROR, 0);
  // TIDY: :[[@LINE-1]]:3: warning: ereport/elog at ERROR or FATAL while holding a spinlock; the lock would stay acquired [pg-unsafe-in-crit-section]
  SpinLockRelease(lock);
}

void ok_palloc_outside(void) {
  palloc(8);
  START_CRIT_SECTION();
  END_CRIT_SECTION();
  palloc(8);
}

void ok_palloc_after_end(void) {
  START_CRIT_SECTION();
  END_CRIT_SECTION();
  palloc(8);
}

void ok_error_context_in_crit(void) {
  START_CRIT_SECTION();
  MemoryContextAlloc(ErrorContext, 8);
  END_CRIT_SECTION();
}

void ok_elog_error_in_crit(void) {
  START_CRIT_SECTION();
  errstart(ERROR, 0); // invariant failure; ERROR is promoted to PANIC
  END_CRIT_SECTION();
}

void ok_branch_start_does_not_leak(int c) {
  if (c)
    START_CRIT_SECTION();
  palloc(8);
  if (c)
    END_CRIT_SECTION();
}

void ok_warning_under_spinlock(void *lock) {
  SpinLockAcquire(lock);
  errstart(WARNING, 0);
  SpinLockRelease(lock);
}

void ok_panic_under_spinlock(void *lock) {
  SpinLockAcquire(lock);
  errstart(PANIC, 0);
  SpinLockRelease(lock);
}

void ok_palloc_after_spin_release(void *lock) {
  SpinLockAcquire(lock);
  SpinLockRelease(lock);
  palloc(8);
}

void ok_nested_crit(void) {
  START_CRIT_SECTION();
  START_CRIT_SECTION();
  END_CRIT_SECTION();
  palloc(8);
  // TIDY: :[[@LINE-1]]:3: warning: allocation with 'palloc' in a critical section
  END_CRIT_SECTION();
}
