int __sigsetjmp(void);
void pg_re_throw(void);
void FlushErrorState(void);
void ReThrowError(void *edata);
void *CopyErrorData(void);
void ereport(int elevel, ...);
void cleanup(void);
void PLy_spi_subtransaction_abort(void);
void unknown_helper(void);

void helper_that_flushes(void) {
    FlushErrorState();
}

void warn_empty_catch(void) {
    if (__sigsetjmp() == 0) {
    } else {
        // TIDY: :[[@LINE-1]]:12: warning: PG_CATCH block neither flushes nor rethrows the error; call FlushErrorState(), PG_RE_THROW(), or ReThrowError() so the errordata stack is not leaked [pg-catch-missing-flush-or-rethrow]
        cleanup();
    }
}

void warn_ereport_in_catch(void) {
    if (__sigsetjmp() == 0) {
    } else {
        // TIDY: :[[@LINE-1]]:12: warning: PG_CATCH block neither flushes nor rethrows the error
        ereport(20, 0);
    }
}

void warn_copy_without_flush(void) {
    if (__sigsetjmp() == 0) {
    } else {
        // TIDY: :[[@LINE-1]]:12: warning: PG_CATCH block neither flushes nor rethrows the error
        CopyErrorData();
    }
}

void warn_unknown_helper(void) {
    if (__sigsetjmp() == 0) {
    } else {
        // TIDY: :[[@LINE-1]]:12: warning: PG_CATCH block neither flushes nor rethrows the error
        unknown_helper();
    }
}

void ok_rethrow(void) {
    if (__sigsetjmp() == 0) {
    } else {
        cleanup();
        pg_re_throw();
    }
}

void ok_flush(void) {
    if (__sigsetjmp() == 0) {
    } else {
        FlushErrorState();
    }
}

void ok_rethrow_error(void) {
    if (__sigsetjmp() == 0) {
    } else {
        void *edata = CopyErrorData();
        FlushErrorState();
        ReThrowError(edata);
    }
}

void ok_same_tu_helper(void) {
    if (__sigsetjmp() == 0) {
    } else {
        helper_that_flushes();
    }
}

void ok_cross_tu_subtrans_abort(void) {
    if (__sigsetjmp() == 0) {
    } else {
        PLy_spi_subtransaction_abort();
    }
}

void ok_finally(void) {
    int _do_rethrow = 0;
    if (__sigsetjmp() == 0) {
    } else
        _do_rethrow = 1;
    {
        cleanup();
    }
    if (_do_rethrow)
        pg_re_throw();
}
