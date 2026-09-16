typedef unsigned long Size;
void *palloc(Size size);
void *palloc0(Size size);
void *palloc_mul(Size s1, Size s2);
void *repalloc(void *pointer, Size size);
void *MemoryContextAlloc(void *context, Size size);
Size mul_size(Size s1, Size s2);

struct Item {
    int x;
};

void *warn_runtime_times_sizeof(int n) {
    return palloc(n * sizeof(struct Item));
    // TIDY: :[[@LINE-1]]:12: warning: allocation size multiplies a runtime value without overflow checking; use mul_size(), palloc_array(), or palloc_mul() [pg-palloc-runtime-mul]
}

void *warn_sizeof_times_runtime(int n) {
    return palloc(sizeof(struct Item) * n);
    // TIDY: :[[@LINE-1]]:12: warning: allocation size multiplies a runtime value without overflow checking
}

void *warn_two_runtime_values(int n, int m) {
    return palloc(n * m);
    // TIDY: :[[@LINE-1]]:12: warning: allocation size multiplies a runtime value without overflow checking
}

void *warn_flexible_array(int n) {
    return palloc(sizeof(struct Item) + n * sizeof(int));
    // TIDY: :[[@LINE-1]]:12: warning: allocation size multiplies a runtime value without overflow checking
}

void *warn_palloc0(int n) {
    return palloc0(n * sizeof(int));
    // TIDY: :[[@LINE-1]]:12: warning: allocation size multiplies a runtime value without overflow checking
}

void *warn_repalloc(void *p, int n) {
    return repalloc(p, n * sizeof(int));
    // TIDY: :[[@LINE-1]]:12: warning: allocation size multiplies a runtime value without overflow checking
}

void *warn_memory_context(void *ctx, int n) {
    return MemoryContextAlloc(ctx, n * sizeof(int));
    // TIDY: :[[@LINE-1]]:12: warning: allocation size multiplies a runtime value without overflow checking
}

void *warn_via_local(int n) {
    Size sz = n * sizeof(struct Item);
    return palloc(sz);
    // TIDY: :[[@LINE-1]]:12: warning: allocation size multiplies a runtime value without overflow checking
}

void *ok_times_one(int n) {
    return palloc(n * sizeof(char)); // sizeof(char) == 1, no overflow
}

void *ok_times_one_literal(int n) {
    return palloc(n * 1); // no warning
}

void *ok_constant_product(void) {
    return palloc(16 * 4); // no warning
}

void *ok_sizeof_only(void) {
    return palloc(sizeof(struct Item)); // no warning
}

void *ok_mul_size(int n) {
    return palloc(mul_size(n, sizeof(struct Item))); // no warning
}

void *ok_palloc_mul(int n) {
    return palloc_mul(sizeof(struct Item), n); // no warning
}

void *ok_addition(int n) {
    return palloc(n + sizeof(struct Item)); // no warning
}

void *palloc_mul(Size s1, Size s2) {
    Size req = s1; // helper body should not warn even if it later pallocs
    (void)s2;
    return palloc(req);
}
