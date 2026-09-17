int __sigsetjmp(void);
void pg_re_throw(void);
void FlushErrorState(void);
void ReThrowError(void *edata);
void *CopyErrorData(void);
void *MemoryContextSwitchTo(void *ctx);
void *CurrentMemoryContext;
int errstart(int elevel, const char *domain);
void cleanup(void);
void PLy_spi_subtransaction_abort(void);
void AbortOutOfAnyTransaction(void);
void StartTransactionCommand(void);
void unknown_helper(void);

#define ERROR 21
#define WARNING 19

void helper_that_switches(void) {
    MemoryContextSwitchTo(CurrentMemoryContext);
    FlushErrorState();
}

void warn_flush_without_switch(void) {
    if (__sigsetjmp() == 0) {
    } else {
        // TIDY: :[[@LINE-1]]:12: warning: PG_CATCH continues without restoring memory context; call MemoryContextSwitchTo() before FlushErrorState() or PG_RE_THROW() so CurrentMemoryContext is not left as ErrorContext [pg-missing-memory-context-restore]
        FlushErrorState();
    }
}

void warn_empty_catch(void) {
    if (__sigsetjmp() == 0) {
    } else {
        // TIDY: :[[@LINE-1]]:12: warning: PG_CATCH continues without restoring memory context
        cleanup();
    }
}

void warn_unknown_helper(void) {
    if (__sigsetjmp() == 0) {
    } else {
        // TIDY: :[[@LINE-1]]:12: warning: PG_CATCH continues without restoring memory context
        unknown_helper();
    }
}

void ok_switch_then_flush(void) {
    void *old = CurrentMemoryContext;
    if (__sigsetjmp() == 0) {
    } else {
        MemoryContextSwitchTo(old);
        FlushErrorState();
    }
}

void ok_assign_current(void) {
    void *old = CurrentMemoryContext;
    if (__sigsetjmp() == 0) {
    } else {
        CurrentMemoryContext = old;
        FlushErrorState();
    }
}

void ok_rethrow(void) {
    if (__sigsetjmp() == 0) {
    } else {
        cleanup();
        pg_re_throw();
    }
}

void ok_rethrow_error(void) {
    if (__sigsetjmp() == 0) {
    } else {
        void *edata = CopyErrorData();
        ReThrowError(edata);
    }
}

void ok_ereport_error(void) {
    if (__sigsetjmp() == 0) {
    } else {
        errstart(ERROR, 0);
    }
}

void ok_same_tu_helper(void) {
    if (__sigsetjmp() == 0) {
    } else {
        helper_that_switches();
    }
}

void ok_cross_tu_subtrans_abort(void) {
    if (__sigsetjmp() == 0) {
    } else {
        PLy_spi_subtransaction_abort();
    }
}

void ok_abort_and_restart_xact(void) {
    if (__sigsetjmp() == 0) {
    } else {
        AbortOutOfAnyTransaction();
        FlushErrorState();
        StartTransactionCommand();
    }
}

void ok_warning_not_enough_but_switch(void) {
    void *old = CurrentMemoryContext;
    if (__sigsetjmp() == 0) {
    } else {
        MemoryContextSwitchTo(old);
        errstart(WARNING, 0);
        FlushErrorState();
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
