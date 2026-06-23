// RUN: clang-tidy -load=%tidy_plugin -checks='-*,postgres-return-in-pg-try-block' %s -- | FileCheck %s --check-prefix=TIDY
// RUN: clang -cc1 -load %analyzer_plugin -analyze -analyzer-checker=alpha.postgres.ReturnInPgTryBlockChecker %s 2>&1 | FileCheck %s --check-prefix=ANALYZER

int __sigsetjmp(void);

void test_return() {
    if (__sigsetjmp() == 0) {
        return; 
        // TIDY: :[[@LINE-1]]:9: warning: unsafe return statement is used inside PG_TRY block [postgres-return-in-pg-try-block]
        // ANALYZER: :[[@LINE-2]]:9: error: unsafe return statement is used inside PG_TRY block
    }
}

void test_break() {
    while (1) {
        if (__sigsetjmp() == 0) {
            break; 
            // TIDY: :[[@LINE-1]]:13: warning: break statement is used inside PG_TRY block which is unsafe [postgres-return-in-pg-try-block]
            // ANALYZER: :[[@LINE-2]]:13: error: break statement is used inside PG_TRY block which is unsafe
        }
    }
}

void test_continue() {
    while (1) {
        if (__sigsetjmp() == 0) {
            continue; 
            // TIDY: :[[@LINE-1]]:13: warning: continue statement is used inside PG_TRY block which is unsafe [postgres-return-in-pg-try-block]
            // ANALYZER: :[[@LINE-2]]:13: error: continue statement is used inside PG_TRY block which is unsafe
        }
    }
}

void test_goto() {
    if (__sigsetjmp() == 0) {
        goto out; 
        // TIDY: :[[@LINE-1]]:9: warning: unsafe goto statement is used inside PG_TRY block [postgres-return-in-pg-try-block]
        // ANALYZER: :[[@LINE-2]]:9: error: unsafe goto statement is used inside PG_TRY block
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
