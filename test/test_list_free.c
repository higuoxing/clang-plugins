// RUN: clang-tidy -load=%tidy_plugin -checks='-*,postgres-list-free' %s -- | FileCheck %s --check-prefix=TIDY
// RUN: clang -cc1 -load %analyzer_plugin -analyze -analyzer-checker=alpha.postgres.ListFreeChecker %s 2>&1 | FileCheck %s --check-prefix=ANALYZER

typedef struct List List;
void pfree(void *pointer);

void list_free_private(List *list) {
    pfree(list); // Should not warn
}

void my_func(List *list) {
    pfree(list); 
    // TIDY: :[[@LINE-1]]:5: warning: Applying pfree() on a list is not allowed. Use list_free() instead. [postgres-list-free]
    // ANALYZER: :[[@LINE-2]]:5: warning: Freeing a (List *) with pfree() [alpha.postgres.ListFreeChecker]
}
