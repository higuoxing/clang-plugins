typedef int Buffer;
typedef unsigned int BlockNumber;
typedef unsigned int uint32;

void PredicateLockPage(void *rel, BlockNumber blkno, void *snapshot);
void ReleaseBuffer(Buffer buf);
BlockNumber BufferGetBlockNumber(Buffer buffer);
void takes_uint32(uint32 x);

void warn_buffer_as_blocknumber(Buffer buf, void *rel, void *snap) {
    PredicateLockPage(rel, buf, snap);
    // TIDY: :[[@LINE-1]]:28: warning: passing 'Buffer' where 'BlockNumber' is expected; Buffer is a buffer identifier, BlockNumber is a page number [pg-typedef-mismatch]
}

void warn_blocknumber_as_buffer(BlockNumber blkno) {
    ReleaseBuffer(blkno);
    // TIDY: :[[@LINE-1]]:19: warning: passing 'BlockNumber' where 'Buffer' is expected; Buffer is a buffer identifier, BlockNumber is a page number [pg-typedef-mismatch]
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

void ok_matching_typedefs(Buffer buf, BlockNumber blkno, void *rel,
                          void *snap) {
    ReleaseBuffer(buf);
    PredicateLockPage(rel, blkno, snap);
}

void ok_explicit_cast(Buffer buf, void *rel, void *snap) {
    PredicateLockPage(rel, (BlockNumber)buf, snap);
}

void ok_plain_uint32_is_not_blocknumber(Buffer buf, uint32 n) {
    takes_uint32(n);
    ReleaseBuffer(buf);
}
