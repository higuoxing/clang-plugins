int __sigsetjmp(void);

void test_return() {
    if (__sigsetjmp() == 0) {
        return; 
        // CHECK: :[[@LINE-1]]:9: warning: unsafe return statement is used inside PG_TRY block [pg-return-in-pg-try-block]
    }
}

void test_break() {
    while (1) {
        if (__sigsetjmp() == 0) {
            break; 
            // CHECK: :[[@LINE-1]]:13: warning: break statement is used inside PG_TRY block which is unsafe [pg-return-in-pg-try-block]
        }
    }
}

void test_continue() {
    while (1) {
        if (__sigsetjmp() == 0) {
            continue; 
            // CHECK: :[[@LINE-1]]:13: warning: continue statement is used inside PG_TRY block which is unsafe [pg-return-in-pg-try-block]
        }
    }
}

void test_goto() {
    if (__sigsetjmp() == 0) {
        goto out; 
        // CHECK: :[[@LINE-1]]:9: warning: unsafe goto statement is used inside PG_TRY block [pg-return-in-pg-try-block]
    }
out:
    return;
}

void test_safe_loops() {
    if (__sigsetjmp() == 0) {
        while (1) {
            break; // Safe
            continue; // Safe
        }
    }
}
