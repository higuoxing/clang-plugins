volatile unsigned InterruptHoldoffCount;
volatile unsigned QueryCancelHoldoffCount;

#define HOLD_INTERRUPTS() (InterruptHoldoffCount++)
#define RESUME_INTERRUPTS()                                                    \
  do {                                                                         \
    InterruptHoldoffCount--;                                                   \
  } while (0)

#define HOLD_CANCEL_INTERRUPTS() (QueryCancelHoldoffCount++)
#define RESUME_CANCEL_INTERRUPTS()                                             \
  do {                                                                         \
    QueryCancelHoldoffCount--;                                                 \
  } while (0)

void warn_early_return(int c) {
  HOLD_INTERRUPTS();
  if (c)
    return;
    // TIDY: :[[@LINE-1]]:5: warning: HOLD_INTERRUPTS() without matching RESUME_INTERRUPTS() on this path; leaked InterruptHoldoffCount blocks CHECK_FOR_INTERRUPTS() [pg-unbalanced-hold-interrupts]
  RESUME_INTERRUPTS();
}

int warn_return_value(int c) {
  HOLD_INTERRUPTS();
  if (c)
    return 1;
    // TIDY: :[[@LINE-1]]:5: warning: HOLD_INTERRUPTS() without matching RESUME_INTERRUPTS() on this path
  RESUME_INTERRUPTS();
  return 0;
}

int warn_eof_before_resume(int qtype) {
  HOLD_CANCEL_INTERRUPTS();
  if (qtype < 0)
    return qtype;
    // TIDY: :[[@LINE-1]]:5: warning: HOLD_CANCEL_INTERRUPTS() without matching RESUME_CANCEL_INTERRUPTS() on this path; leaked QueryCancelHoldoffCount blocks query cancel [pg-unbalanced-hold-interrupts]
  RESUME_CANCEL_INTERRUPTS();
  return qtype;
}

void ok_balanced(void) {
  HOLD_INTERRUPTS();
  RESUME_INTERRUPTS();
}

void ok_early_return_after_resume(int c) {
  HOLD_INTERRUPTS();
  if (c) {
    RESUME_INTERRUPTS();
    return;
  }
  RESUME_INTERRUPTS();
}

// Acquire-style: HOLD and return still held. No later RESUME in this
// function, so the caller is expected to resume.
void ok_acquire_returns_held(void) {
  HOLD_INTERRUPTS();
}

// Conditional acquire: resume only on the failure branch, then return
// still held on success. The return is after the if, not an early skip
// of a later RESUME.
int ok_conditional_acquire(int mustwait) {
  HOLD_INTERRUPTS();
  if (mustwait)
    RESUME_INTERRUPTS();
  return !mustwait;
}

void ok_branch_hold_does_not_leak(int c) {
  if (c)
    HOLD_INTERRUPTS();
  if (c)
    RESUME_INTERRUPTS();
}

void ok_nested(void) {
  HOLD_INTERRUPTS();
  HOLD_INTERRUPTS();
  RESUME_INTERRUPTS();
  RESUME_INTERRUPTS();
}

void ok_cancel_balanced(void) {
  HOLD_CANCEL_INTERRUPTS();
  RESUME_CANCEL_INTERRUPTS();
}
