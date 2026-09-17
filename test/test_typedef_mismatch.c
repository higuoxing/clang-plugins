typedef int Buffer;
typedef unsigned int BlockNumber;
typedef unsigned short OffsetNumber;
typedef short AttrNumber;
typedef unsigned int uint32;
typedef unsigned int Oid;
typedef unsigned int TransactionId;
typedef unsigned int CommandId;
typedef long Timestamp;
typedef long TimestampTz;

void PredicateLockPage(void *rel, BlockNumber blkno, void *snapshot);
void ReleaseBuffer(Buffer buf);
BlockNumber BufferGetBlockNumber(Buffer buffer);
void PageGetItemId(void *page, OffsetNumber off);
void ginFillScanKey(void *so, OffsetNumber attnum);
void HeapTupleHeaderSetCmin(void *tup, CommandId cid);
void takes_uint32(uint32 x);
void takes_xid(TransactionId xid);
void takes_oid(Oid oid);
void takes_attr(AttrNumber attno);
void timestamp2tm(Timestamp t);
#define InvalidTransactionId ((TransactionId) 0)

void warn_buffer_as_blocknumber(Buffer buf, void *rel, void *snap) {
    PredicateLockPage(rel, buf, snap);
    // TIDY: :[[@LINE-1]]:28: warning: passing 'Buffer' where 'BlockNumber' is expected; these identify different page/item locations [pg-typedef-mismatch]
}

void warn_blocknumber_as_buffer(BlockNumber blkno) {
    ReleaseBuffer(blkno);
    // TIDY: :[[@LINE-1]]:19: warning: passing 'BlockNumber' where 'Buffer' is expected; these identify different page/item locations [pg-typedef-mismatch]
}

void warn_offset_as_blocknumber(OffsetNumber off, void *rel, void *snap) {
    PredicateLockPage(rel, off, snap);
    // TIDY: :[[@LINE-1]]:28: warning: passing 'OffsetNumber' where 'BlockNumber' is expected; these identify different page/item locations [pg-typedef-mismatch]
}

void warn_buffer_as_offset(Buffer buf) {
    PageGetItemId(0, buf);
    // TIDY: :[[@LINE-1]]:22: warning: passing 'Buffer' where 'OffsetNumber' is expected; these identify different page/item locations [pg-typedef-mismatch]
}

void warn_attr_as_blocknumber(AttrNumber attno, void *rel, void *snap) {
    PredicateLockPage(rel, attno, snap);
    // TIDY: :[[@LINE-1]]:28: warning: passing 'AttrNumber' where 'BlockNumber' is expected; an attribute number is not a buffer or page number [pg-typedef-mismatch]
}

void warn_oid_as_xid(Oid oid) {
    takes_xid(oid);
    // TIDY: :[[@LINE-1]]:15: warning: passing 'Oid' where 'TransactionId' is expected; an object id is not a transaction id [pg-typedef-mismatch]
}

void warn_xid_as_oid(TransactionId xid) {
    takes_oid(xid);
    // TIDY: :[[@LINE-1]]:15: warning: passing 'TransactionId' where 'Oid' is expected; an object id is not a transaction id [pg-typedef-mismatch]
}

void warn_member_buffer_as_blocknumber(void *rel, void *snap) {
    struct Stack {
        Buffer buffer;
    } stack;
    PredicateLockPage(rel, stack.buffer, snap);
    // TIDY: :[[@LINE-1]]:28: warning: passing 'Buffer' where 'BlockNumber' is expected
}

void ok_buffergetblocknumber(Buffer buf, void *rel, void *snap) {
    PredicateLockPage(rel, BufferGetBlockNumber(buf), snap);
}

void ok_matching_typedefs(Buffer buf, BlockNumber blkno, OffsetNumber off,
                          AttrNumber attno, void *rel, void *snap) {
    ReleaseBuffer(buf);
    PredicateLockPage(rel, blkno, snap);
    PageGetItemId(0, off);
    takes_attr(attno);
}

void ok_explicit_cast(Buffer buf, void *rel, void *snap) {
    PredicateLockPage(rel, (BlockNumber)buf, snap);
}

void ok_plain_uint32_is_not_blocknumber(Buffer buf, uint32 n) {
    takes_uint32(n);
    ReleaseBuffer(buf);
}

// GIN stores index attnum in an OffsetNumber field.
void ok_gin_attr_as_offset(AttrNumber attno) {
    ginFillScanKey(0, attno);
}

// FDW / heap_form_tuple stomp cmin with InvalidTransactionId (zero).
void ok_cmin_invalid_xid(void *tup) {
    HeapTupleHeaderSetCmin(tup, InvalidTransactionId);
}

void ok_timestamp_tz_as_timestamp(TimestampTz ts) {
    timestamp2tm(ts);
}
