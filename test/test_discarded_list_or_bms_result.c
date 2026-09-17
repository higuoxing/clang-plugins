void *lappend(void *list, void *datum);
void *lappend_int(void *list, int datum);
void *lcons(void *datum, void *list);
void *list_delete_first(void *list);
void *list_concat(void *list1, void *list2);
void *list_copy(void *list);
void *bms_add_member(void *a, int x);
void *bms_del_member(void *a, int x);
void *bms_union(void *a, void *b);

void warn_lappend(void *list, void *x) {
  lappend(list, x);
  // TIDY: :[[@LINE-1]]:3: warning: result of 'lappend' discarded; the pointer may have been reallocated, so assign it back (e.g. list = lappend(list, x)) [pg-discarded-list-or-bms-result]
}

void warn_lcons(void *list, void *x) {
  lcons(x, list);
  // TIDY: :[[@LINE-1]]:3: warning: result of 'lcons' discarded
}

void warn_list_delete_first(void *list) {
  list_delete_first(list);
  // TIDY: :[[@LINE-1]]:3: warning: result of 'list_delete_first' discarded
}

void warn_list_concat(void *list, void *x) {
  list_concat(list, x);
  // TIDY: :[[@LINE-1]]:3: warning: result of 'list_concat' discarded
}

void warn_bms_add_member(void *a, int x) {
  bms_add_member(a, x);
  // TIDY: :[[@LINE-1]]:3: warning: result of 'bms_add_member' discarded
}

void warn_bms_del_member(void *a, int x) {
  bms_del_member(a, x);
  // TIDY: :[[@LINE-1]]:3: warning: result of 'bms_del_member' discarded
}

void warn_comma(void *list, void *x) {
  lappend(list, x), (void)0;
  // TIDY: :[[@LINE-1]]:3: warning: result of 'lappend' discarded
}

void warn_if_body(void *list, void *x, int c) {
  if (c)
    lappend(list, x);
  // TIDY: :[[@LINE-1]]:5: warning: result of 'lappend' discarded
}

void warn_ternary_stmt(void *list, void *x, int c) {
  c ? lappend(list, x) : list;
  // TIDY: :[[@LINE-1]]:7: warning: result of 'lappend' discarded
}

void *ok_assign(void *list, void *x) {
  list = lappend(list, x);
  return list;
}

void *ok_return(void *list, void *x) {
  return lappend(list, x);
}

void ok_void_cast(void *list, void *x) {
  (void)lappend(list, x);
}

int ok_condition(void *list, void *x) {
  if (lappend(list, x))
    return 1;
  return 0;
}

void *ok_arg(void *list, void *x) {
  return list_concat(list, lappend(list, x));
}

void *ok_ternary_assign(void *list, void *x, int c) {
  return c ? lappend(list, x) : list;
}

void ok_copy_not_recycling(void *list) {
  list_copy(list);
}

void ok_union_not_recycling(void *a, void *b) {
  bms_union(a, b);
}
