#pragma once
#include <sys/types.h>
/* For allocating trampolines - this is just a mmap wrapper. */
int execmem_alloc_unsealed(uintptr_t hint, void **page_p, uintptr_t *vma_p, size_t *size_p, void *opt);
int execmem_seal(void *page, void *opt);
void execmem_free(void *page, void *opt);

/* Write to "foreign" (i.e. owned by another library, not out-of-process) pages
 * which are already RX or have unknown permissions.
 * If callback is not NULL, run it on all other threads 'atomically', in the
 * sense that it will be called on any thread which executed any of the old
 * instructions in the write region.
 * Oh, and it might mutate 'writes' (to sort it). */
struct execmem_foreign_write {
    void *dst;
    const void *src;
    size_t len;
    void *opt;
};
typedef uintptr_t (*execmem_pc_patch_callback)(void *ctx, uintptr_t pc);
int execmem_foreign_write_with_pc_patch(struct execmem_foreign_write *writes,
                                        size_t nwrites,
                                        execmem_pc_patch_callback callback,
                                        void *callback_ctx);
