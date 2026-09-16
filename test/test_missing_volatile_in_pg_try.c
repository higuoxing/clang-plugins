int __sigsetjmp(void);
void use(int x);
void pg_re_throw(void);

void warn_assigned_then_read(void) {
    int x = 0;
    if (__sigsetjmp() == 0) {
        x = 1;
    } else {
        use(x);
        // TIDY: :[[@LINE-1]]:13: warning: local variable 'x' is modified in PG_TRY and read in PG_CATCH without being declared volatile; its value after longjmp is indeterminate [pg-missing-volatile-in-pg-try]
    }
}

void warn_increment_then_compare(void) {
    int n = 0;
    if (__sigsetjmp() == 0) {
        n++;
    } else {
        if (n)
        // TIDY: :[[@LINE-1]]:13: warning: local variable 'n' is modified in PG_TRY and read in PG_CATCH without being declared volatile
            use(n);
    }
}

void warn_param(int fd) {
    if (__sigsetjmp() == 0) {
        fd = -1;
    } else {
        if (fd >= 0)
        // TIDY: :[[@LINE-1]]:13: warning: local variable 'fd' is modified in PG_TRY and read in PG_CATCH without being declared volatile
            use(fd);
    }
}

void warn_finally(void) {
    int x = 0;
    int _do_rethrow = 0;
    if (__sigsetjmp() == 0) {
        x = 1;
    } else
        _do_rethrow = 1;
    {
        use(x);
        // TIDY: :[[@LINE-1]]:13: warning: local variable 'x' is modified in PG_TRY and read in PG_FINALLY without being declared volatile
    }
    if (_do_rethrow)
        pg_re_throw();
}

void warn_compound_assign_in_catch(void) {
    int x = 0;
    if (__sigsetjmp() == 0) {
        x = 1;
    } else {
        x += 1;
        // TIDY: :[[@LINE-1]]:9: warning: local variable 'x' is modified in PG_TRY and read in PG_CATCH without being declared volatile
    }
}

void ok_volatile(void) {
    volatile int x = 0;
    if (__sigsetjmp() == 0) {
        x = 1;
    } else {
        use(x); // no warning
    }
}

void ok_not_modified_in_try(void) {
    int x = 0;
    if (__sigsetjmp() == 0) {
        use(x);
    } else {
        use(x); // no warning: not written in PG_TRY
    }
}

void ok_not_read_in_catch(void) {
    int x = 0;
    if (__sigsetjmp() == 0) {
        x = 1;
    } else {
        x = 0; // write-only in CATCH; does not read the TRY value
    }
}

void ok_unrelated_var(void) {
    int x = 0;
    int y = 0;
    if (__sigsetjmp() == 0) {
        x = 1;
    } else {
        use(y); // no warning
    }
}

void ok_reassigned_in_catch(void) {
    int x = 0;
    if (__sigsetjmp() == 0) {
        x = 1;
    } else {
        x = 2;
        use(x); // uses the CATCH assignment, not the clobbered TRY value
    }
}

void ok_reinit_then_increment(void) {
    int j = 0;
    if (__sigsetjmp() == 0) {
        j++;
    } else {
        // CATCH writes j before the increment reads it (xpath.c cleanup loop).
        for (j = 1; j < 3; j++)
            use(j);
    }
}

void take_ptr(int *p);

void ok_address_of_in_catch(void) {
    int w = 0;
    if (__sigsetjmp() == 0) {
        w = 1;
    } else {
        take_ptr(&w); // address-of is not a load of the clobbered value
    }
}

void warn_increment_in_catch(void) {
    int k = 0;
    if (__sigsetjmp() == 0) {
        k = 1;
    } else {
        k++;
        // TIDY: :[[@LINE-1]]:9: warning: local variable 'k' is modified in PG_TRY and read in PG_CATCH without being declared volatile
    }
}

void ok_static(void) {
    static int x = 0;
    if (__sigsetjmp() == 0) {
        x = 1;
    } else {
        use(x); // static storage is not clobbered by longjmp
    }
}

void warn_partial_reassign(int c) {
    int x = 0;
    if (__sigsetjmp() == 0) {
        x = 1;
    } else {
        if (c)
            x = 2;
        use(x);
        // TIDY: :[[@LINE-1]]:13: warning: local variable 'x' is modified in PG_TRY and read in PG_CATCH without being declared volatile
    }
}

void ok_reassign_both_paths(int c) {
    int x = 0;
    if (__sigsetjmp() == 0) {
        x = 1;
    } else {
        if (c)
            x = 2;
        else
            x = 3;
        use(x); // assigned on every CATCH path
    }
}

void warn_rhs_reads_clobbered(void) {
    int x = 0;
    if (__sigsetjmp() == 0) {
        x = 1;
    } else {
        x = x + 1;
        // TIDY: :[[@LINE-1]]:13: warning: local variable 'x' is modified in PG_TRY and read in PG_CATCH without being declared volatile
    }
}
