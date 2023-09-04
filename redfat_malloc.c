/*
 *
 *  _|_|_|                    _|  _|_|_|_|            _|      
 *  _|    _|    _|_|      _|_|_|  _|        _|_|_|  _|_|_|_|  
 *  _|_|_|    _|_|_|_|  _|    _|  _|_|_|  _|    _|    _|      
 *  _|    _|  _|        _|    _|  _|      _|    _|    _|      
 *  _|    _|    _|_|_|    _|_|_|  _|        _|_|_|      _|_|  
 * 
 * Gregory J. Duck.
 *
 * Copyright (c) 2022 The National University of Singapore.
 * All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include <assert.h>
#include <pthread.h>

#ifndef REDFAT_LOG
#define REDFAT_DEBUG(msg, ...)          /* NOP */
#else
#define REDFAT_DEBUG(msg, ...)                                          \
    do {                                                                \
        fprintf(stderr, (msg), ##__VA_ARGS__);                          \
    } while (false)
#endif

#define REDFAT_BIG_OBJECT           (16 * REDFAT_PAGE_SIZE)
#define REDFAT_NUM_PAGES(size)                                          \
    ((((size) - 1) / REDFAT_PAGE_SIZE) + 1)
#define REDFAT_PAGES_BASE(ptr)                                          \
    ((void *)((uint8_t *)(ptr) - ((uintptr_t)(ptr) % REDFAT_PAGE_SIZE)))
#define REDFAT_PAGES_SIZE(ptr, size)                                    \
    (REDFAT_NUM_PAGES(((uint8_t *)(ptr) -                               \
        (uint8_t *)REDFAT_PAGES_BASE(ptr)) + (size)) * REDFAT_PAGE_SIZE)

void redfat_init(void);
static size_t redfat_get_buffer_size(const void *ptr_0);

/*
 * Allocator data-structures.
 */
struct redfat_node_s
{
    size_t size;
    uint64_t canary;
    uint8_t object[];
};
typedef struct redfat_node_s *redfat_node_t;

#define redfat_fallback_malloc(x)       libc_malloc(x)
#define redfat_fallback_free(x)         libc_free(x)
#define redfat_fallback_realloc(x, y)   libc_realloc((x), (y))

static redfat_node_t redfat_node(void *ptr)
{
    return (redfat_node_t)redfat_base(ptr);
}

/*
 * LowFat local+global allocator.
 */

struct redfat_freelist_s
{
    uint32_t length;                // Free Queue length
    uint32_t minlen;                // Free Queue min length
    uint32_t head;                  // Free Queue head
    uint32_t tail;                  // Free Queue tail
};

struct redfat_global_s
{
    redfat_mutex_t mutex;           // Mutex
    size_t size;                    // Allocation size (cached here)
    size_t n;                       // Max n for local
    void *startptr;                 // Start pointer
    void *endptr;                   // End pointer
    void *freeptr;                  // Next free metadata pointer
    void *accessptr;                // Next accessible memory pointer

    size_t baseidx;                 // Object base index
    uint32_t freed;                 // Batch of free'ed objects
    uint32_t fresh;                 // Batch of fresh objects
    size_t batchsz;                 // Batch size

    struct redfat_freelist_s Q;     // Free list
};
typedef struct redfat_global_s *redfat_global_t;

struct redfat_local_s
{
    size_t   n;                     // Current n for local
    uint32_t head;                  // Queue head
    uint32_t tail;                  // Queue tail
};
typedef struct redfat_local_s *redfat_local_t;

#define NIL             INT32_MAX   // "NULL" pointer
#define ALLOCED         0x80000000  // Object is allocated

struct redfat_metadata_s
{
    uint32_t next;                  // Next object in chain
};
typedef struct redfat_metadata_s *redfat_metadata_t;

static redfat_metadata_t redfat_metadatas = NULL;
static struct redfat_global_s redfat_global[REDFAT_NUM_REGIONS+1];
static __thread struct redfat_local_s redfat_local[REDFAT_NUM_REGIONS+1] = {0};
static __thread bool redfat_local_disable = false;

/*
 * Prototypes.
 */
static void redfat_thread_exit(void *object);
static void redfat_thread_start(void *object);

/*
 * Initialize the freelist metadata.
 */
static void redfat_malloc_init(void)
{
    redfat_rand(&redfat_canary, sizeof(redfat_canary));

    size_t baseidx = 0;
    for (size_t i = 0; i < REDFAT_NUM_REGIONS; i++)
    {
        size_t idx = i+1;
        uint8_t *heapptr = (uint8_t *)redfat_region(idx);
        size_t size      = redfat_size(heapptr);
        uint32_t roffset = 0;   // Offset for ASLR
        if (redfat_option_aslr_mode)
            redfat_rand(&roffset, sizeof(roffset));
        roffset &= REDFAT_HEAP_ASLR_MASK;
        uint8_t *startptr =
            (uint8_t *)redfat_base(heapptr + roffset + size + REDFAT_PAGE_SIZE);
        redfat_global_t global = redfat_global + idx;
        if (!redfat_mutex_init(&global->mutex))
            redfat_error("failed to initialize mutex");
        global->size      = size;
        global->baseidx   = baseidx;
        global->freed     = NIL;
        global->fresh     = NIL;
        global->Q.length  = 0;
        global->Q.minlen  = redfat_option_quarantine / size;
        global->Q.head    = NIL;
        global->Q.tail    = NIL;
        global->freeptr   = startptr;
        global->startptr  = startptr;
        global->endptr    = startptr + REDFAT_HEAP_MEMORY_SIZE;
        global->accessptr = REDFAT_PAGES_BASE(startptr);
        
        global->n = (size >= REDFAT_PAGE_SIZE? 1: REDFAT_PAGE_SIZE / size);
        global->n = (global->n > 16? 16: global->n);
        global->batchsz = 2 * REDFAT_PAGE_SIZE / size;
        global->batchsz = (global->batchsz == 0? 1: global->batchsz);
        global->batchsz = (global->batchsz >= 256? 256: global->batchsz);
        global->batchsz =
            (global->size == REDFAT_PAGE_SIZE? 1: global->batchsz);
 
        baseidx += (REDFAT_HEAP_MEMORY_SIZE / size) + /*gap=*/16;

        if (redfat_option_reserve)
        {
            void *ptr = mmap(heapptr, REDFAT_REGION_SIZE, PROT_READ,
                MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
            if (ptr != (void *)heapptr)
                redfat_error("failed to mmap memory: %s", strerror(errno));
        }
    }

    uintptr_t base = (REDFAT_NUM_REGIONS + 1) * REDFAT_REGION_SIZE;
    uint32_t roffset;
    redfat_rand(&roffset, sizeof(roffset));
    base += roffset;
    base -= base % REDFAT_PAGE_SIZE;
    size_t size = baseidx * sizeof(struct redfat_metadata_s);
    size = (size % REDFAT_PAGE_SIZE == 0? size:
        (size + REDFAT_PAGE_SIZE) - (size % REDFAT_PAGE_SIZE));
    void *ptr = mmap((void *)base, size, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (ptr != (void *)base)
        redfat_error("failed to mmap memory: %s", strerror(errno));
    redfat_metadatas = (struct redfat_metadata_s *)ptr;

    redfat_thread_start((void *)redfat_local);
}

/*
 * Return the metadata index of a pointer.
 */
static uint32_t redfat_metadata_idx(redfat_global_t global, const void *ptr)
{
    size_t idx = (uint8_t *)ptr - (uint8_t *)global->startptr;
    return (idx / global->size);
}

/*
 * Return the metadata of an index.
 */
static redfat_metadata_t redfat_metadata(redfat_global_t global, uint32_t idx)
{
    return &redfat_metadatas[global->baseidx + (size_t)idx];
}

/*
 * Return the pointer to the object given an index.
 */
static void *redfat_object(redfat_global_t global, uint32_t idx)
{
    void *ptr =
        (void *)((uint8_t *)global->startptr + (size_t)idx * global->size);
    if (ptr >= global->endptr)
    {
        redfat_error("malloc-state-corruption detected!\n"
            "\tpointer = %p\n"
            "\tmax     = %p\n"
            "\tsize    = %zu", ptr, global->endptr, global->size);
    }
    return ptr;
}

/*
 * Push a free'ed object.
 */
static void redfat_global_push_free(redfat_global_t global, uint32_t idx,
    uint32_t next)
{
    redfat_metadata_t metadata = redfat_metadata(global, idx);
    while (true)
    {
        uint32_t new_next = global->freed;
        if (!__sync_bool_compare_and_swap(&metadata->next, next, new_next))
        {
            redfat_node_t node = redfat_object(global, idx);
            redfat_error("double-free detected!\n"
                "\tfunction = %s()\n"
                "\tpointer  = %p", "free", node+1);
        }
        if (__sync_bool_compare_and_swap(&global->freed, new_next, idx))
            break;
        next = new_next;
    }
}

/*
 * Pop a free'ed object.
 */
static uint32_t redfat_global_pop_free(redfat_global_t global)
{
    while (true)
    {
        uint32_t idx = global->freed;
        if (idx == NIL)
            return NIL;
        redfat_metadata_t metadata = redfat_metadata(global, idx);
        uint32_t next = metadata->next;
        if (__sync_bool_compare_and_swap(&global->freed, idx, next))
            return idx;
    }
}

/*
 * Pop a fresh object.
 */
static uint32_t redfat_global_pop_fresh(redfat_global_t global)
{
    uint32_t idx = global->fresh;
    if (idx != NIL)
    {
        redfat_metadata_t metadata = redfat_metadata(global, idx);
        global->fresh = metadata->next;
        return idx;
    }

    // If ASLR is enabled (the default), we allocate fresh objects in
    // "batches", the shuffle the batches using Fisher-Yates.  This shuffles
    // sub-page allocations somewhat, but does not affect the order the pages
    // themselves are used (which is still sequential, for better performance).
    const size_t BATCH_SIZE = 256;
    uint32_t batch[BATCH_SIZE];
    size_t batch_size = global->batchsz;
    if (!redfat_option_aslr_mode)
        batch_size = 1;
    size_t i = 0;
    for (; i < batch_size; i++)
    {
        void *ptr = global->freeptr;
        void *freeptr = (uint8_t *)ptr + global->size;
        if (freeptr > global->endptr)
            break;      // OOM!
        global->freeptr = freeptr;
        void *accessptr = global->accessptr;
        if (freeptr > accessptr)
        {
            uint8_t *map_ptr = (uint8_t *)accessptr;
            size_t map_size = REDFAT_PAGES_SIZE(accessptr, global->size);
            map_size += REDFAT_PAGE_SIZE;
            if (map_size < REDFAT_BIG_OBJECT)
                map_size = REDFAT_BIG_OBJECT;
            errno = 0;
            int flags = MAP_PRIVATE | MAP_ANONYMOUS |
                (redfat_option_reserve? MAP_FIXED: 0x0);
            uint8_t *ptr = (uint8_t *)mmap(map_ptr, map_size,
                PROT_READ | PROT_WRITE, flags, -1, 0);
            if (ptr != map_ptr && errno != 0)
                redfat_error("mmap() failed: %s", strerror(errno));
            if (ptr != map_ptr)
                redfat_error("region #%zu address range %p..%p is already "
                    "occupied", idx, map_ptr, map_ptr + map_size);
            global->accessptr = map_ptr + map_size;
        }
        idx = redfat_metadata_idx(global, ptr);
        batch[i] = idx;
    }
    if (i == 0)
        return NIL;
    uint64_t seed = 0;
    if (i > 1)
        redfat_rand(&seed, sizeof(seed));
    for (; i > 1; i--)
    {
        seed++;
        uint64_t r = seed * 0x96e51baf02cd85fdull;
        uint16_t j = (uint16_t)__builtin_ia32_crc32di(0, r);  // PRNG
        j = j % (uint16_t)i;
        idx      = batch[j];
        batch[j] = batch[i-1];
        redfat_metadata_t metadata = redfat_metadata(global, idx);
        metadata->next = global->fresh;
        global->fresh  = idx;
    }
    return batch[0];
}

/*
 * Queue a free object.
 */
static void redfat_global_queue_free(redfat_global_t global, uint32_t idx)
{
    redfat_metadata_t metadata = redfat_metadata(global, idx);
    metadata->next = NIL;
    if (global->Q.tail == NIL)
        global->Q.tail = global->Q.head = idx;
    else
    {
        redfat_metadata_t tail = redfat_metadata(global, global->Q.tail);
        tail->next = idx;
        global->Q.tail = idx;
    }
    global->Q.length++;
}

/*
 * Unqueue a free object.
 */
static uint32_t redfat_global_unqueue_free(redfat_global_t global)
{
    size_t idx = global->Q.head;
    if (idx == NIL)
        return idx;
    redfat_metadata_t metadata = redfat_metadata(global, idx);
    if (global->Q.head == global->Q.tail)
        global->Q.head = global->Q.tail = NIL;
    else
        global->Q.head = metadata->next;
    global->Q.length--;
    return idx;
}

/*
 * Queue a free object.
 */
static void redfat_local_queue_free(redfat_global_t global,
    redfat_local_t local, uint32_t idx)
{
    redfat_metadata_t metadata = redfat_metadata(global, idx);
    metadata->next = NIL;
    if (local->tail == NIL)
        local->tail = local->head = idx;
    else
    {
        redfat_metadata_t tail = redfat_metadata(global, local->tail);
        local->tail = tail->next = idx;
    }
}

/*
 * Unqueue a free object.
 */
static uint32_t redfat_local_unqueue_free(redfat_global_t global,
    redfat_local_t local)
{
    size_t idx = local->head;
    if (idx == NIL)
        return idx;
    redfat_metadata_t metadata = redfat_metadata(global, idx);
    if (local->head == local->tail)
        local->head = local->tail = NIL;
    else
        local->head = metadata->next;
    return idx;
}

/*
 * Free an metadata to the global allocator (no locking required).
 */
static void redfat_global_free(redfat_global_t global, void *ptr)
{
    uint32_t idx = redfat_metadata_idx(global, ptr);
    redfat_global_push_free(global, idx, ALLOCED);
}

/*
 * Global (locked) allocation.
 */
static void redfat_global_alloc(redfat_global_t global, redfat_local_t local)
{
    redfat_mutex_lock(&global->mutex);

    // Step (1): Collect free objects:
    uint32_t tmp = NIL;
    size_t minlen = global->Q.minlen + local->n;
    size_t diff = (global->Q.length < minlen?  minlen - global->Q.length: 0);
    size_t i = 0;
    for (; i < diff; i++)
    {
        uint32_t idx = redfat_global_pop_free(global);
        if (idx == NIL)
            break;
        redfat_metadata_t metadata = redfat_metadata(global, idx);
        metadata->next = tmp;
        tmp = idx;
    }
    for (; i < diff; i++)
    {
        uint32_t idx = redfat_global_pop_fresh(global);
        if (idx == NIL)
            break;      // OOM!
        redfat_metadata_t metadata = redfat_metadata(global, idx);
        metadata->next = tmp;
        tmp = idx;
    }

    // Step (2): Queue free objects:
    while (tmp != NIL)
    {
        uint32_t idx = tmp;
        redfat_metadata_t metadata = redfat_metadata(global, idx);
        tmp = metadata->next;
        redfat_global_queue_free(global, idx);
    }

    // Step (3): Push free objects to the local cache.
    for (size_t i = 0; i < global->n; i++)
    {
        uint32_t idx = redfat_global_unqueue_free(global);
        if (idx == NIL)
            break;
        redfat_local_queue_free(global, local, idx);
    }

    redfat_mutex_unlock(&global->mutex);

    local->n *= 2;
    local->n = (local->n > global->n? global->n: local->n);
}

/*
 * Local (lock-free) allocation.
 */
static void *redfat_local_alloc(redfat_global_t global, redfat_local_t local)
{
    if (local->head == NIL)
        redfat_global_alloc(global, local);     // Get more objects
    uint32_t idx = redfat_local_unqueue_free(global, local);
    if (idx == NIL)
    {
        errno = ENOMEM;
        return NULL;    // OOM!
    }
    redfat_metadata_t metadata = redfat_metadata(global, idx);
    metadata->next = ALLOCED;
    return redfat_object(global, idx);
}

/*
 * Thread start = initialize redfat_local.
 */
static void redfat_thread_start(void *object)
{
    if (object == NULL)
        return;
    redfat_local_t locals = (redfat_local_t)object;
    for (size_t i = 1; i < REDFAT_NUM_REGIONS+1; i++)
    {
        locals[i].n = 1;
        locals[i].head = locals[i].tail = NIL;
    }
    redfat_local_disable = false;
}

/*
 * Thread exit = return objects.
 */
static void redfat_thread_exit(void *object)
{
    if (object == NULL)
        return;
    redfat_local_t locals = (redfat_local_t)object;
    redfat_local_disable = true;
    for (size_t i = 1; i < REDFAT_NUM_REGIONS+1; i++)
    {
        redfat_global_t global = &redfat_global[i];
        redfat_local_t  local  = &locals[i];
        uint32_t idx;
        while ((idx = local->head) != NIL)
        {
            struct redfat_metadata_s *metadata = redfat_metadata(global, idx);
            local->head = metadata->next;
            redfat_global_push_free(global, idx, metadata->next);
        }
    }
}

/*
 * In "test mode", 1/rate allocations will be 1-byte short.
 */
static inline size_t redfat_test_size(size_t size)
{
    if (redfat_option_test_rate == 0 || size == 0)
        return size;
    uint16_t r;
    redfat_rand(&r, sizeof(r));
    return ((r % redfat_option_test_rate) != 0? size: size-1);
}

/*
 * Allocate a node.
 */
static redfat_node_t redfat_node_malloc(size_t size)
{
    if (!redfat_malloc_inited)
        redfat_init();
    if (redfat_local_disable)
    {
        errno = ENOMEM;
        return NULL;
    }
    size_t ext_size = size + sizeof(struct redfat_node_s) +
        (redfat_option_canary_mode? sizeof(uint64_t): 0);
    size_t idx = redfat_heap_select(ext_size);
    if (idx == 0)
    {
        // Cannot handle this allocation size.
        errno = ENOMEM;
        return NULL;
    }

    redfat_global_t global = &redfat_global[idx];
    redfat_local_t local = &redfat_local[idx];

    redfat_node_t node = redfat_local_alloc(global, local);
    if (node == NULL)
        return node;

    if (redfat_option_profile_mode)
    {
        __sync_fetch_and_add(&redfat_profile_alloc_count, 1);
        __sync_fetch_and_add(&redfat_profile_alloc_bytes, global->size);
    }
    node->size = redfat_test_size(size);
    node->canary = redfat_canary;
    if (redfat_option_canary_mode)
    {
        uint64_t *canary_ptr = (uint64_t *)((uint8_t *)(node + 1) + node->size);
        *canary_ptr = redfat_canary;
    }
    return node;
}

/*
 * Free a node.
 */
static void redfat_node_free(redfat_node_t node)
{
    size_t idx = redfat_index(node);
    redfat_global_t global = &redfat_global[idx];
    void *ptr = (void *)node;
    if (ptr < global->startptr || ptr >= global->freeptr)
        redfat_error("invalid-free detected!\n"
            "\tfunction = %s()\n"
            "\tpointer  = %p",
            "free", node+1);
    size_t size = node->size;
    if (size >= redfat_size(ptr) - REDFAT_REDZONE_SIZE ||
            node->canary != redfat_canary)
        redfat_lib_error(node+1, 0);
    if (redfat_option_canary_mode)
    {
        const uint64_t *canary_ptr =
            (const uint64_t *)((uint8_t *)(node + 1) + size);
        uint64_t canary =
            (size > redfat_size(ptr)-REDFAT_REDZONE_SIZE-sizeof(uint64_t)?
                0x0: *canary_ptr);
        if (canary != redfat_canary)
            redfat_lib_error(node+1, 0);
    }
    if (global->size >= REDFAT_BIG_OBJECT &&
            madvise(ptr, global->size, MADV_DONTNEED) == 0)
        /*NOP*/;
    else if (redfat_option_zero_mode)
        libc_memset(ptr, 0x0, redfat_size(ptr));
    else
        node->size = 0x0;
    redfat_global_free(global, ptr);
}

/*
 * REDFAT malloc()
 */
extern void *redfat_malloc(size_t size)
{
    redfat_node_t node = redfat_node_malloc(size);
    if (node == NULL)
        return redfat_fallback_malloc(size);
    else
    {
        REDFAT_DEBUG("malloc(%zu) = %p [base=%p, size=%zu]\n",
            size, node->object, node, redfat_size(node));
        assert(redfat_size(node) > node->size + REDFAT_REDZONE_SIZE);
        return node->object;
    }
}
extern void *malloc(size_t size) REDFAT_ALIAS("redfat_malloc");

/*
 * REDFAT free()
 */
extern void redfat_free(void *ptr)
{
    if (ptr == NULL)
        return;
    redfat_node_t node = redfat_node(ptr);
    if (node == NULL)
    {
        redfat_fallback_free(ptr);
        return;
    }
    REDFAT_DEBUG("free(%p)\n", ptr);
    redfat_node_free(node);
}
extern void free(void *ptr) REDFAT_ALIAS("redfat_free");

/*
 * REDFAT calloc()
 */
extern void *redfat_calloc(size_t nmemb, size_t size)
{
    void *ptr = redfat_malloc(nmemb * size);
    if (ptr == NULL)
        return ptr;
    libc_memset(ptr, 0, nmemb * size);
    return ptr;
}
extern void *calloc(size_t nmemb, size_t size) REDFAT_ALIAS("redfat_calloc");

/*
 * REDFAT realloc()
 */
static redfat_node_t redfat_node_realloc(redfat_node_t node, size_t size)
{
    // (1) Check for cheap case:
    size_t ext_size = size + sizeof(struct redfat_node_s) +
        (redfat_option_canary_mode? sizeof(uint64_t): 0);
    if (redfat_index(node) == redfat_heap_select(ext_size))
    {
        node->size = size;
        if (redfat_option_canary_mode)
        {
            uint64_t *canary_ptr =
                (uint64_t *)((uint8_t *)(node + 1) + node->size);
            *canary_ptr = redfat_canary;
        }
        return node;
    }

    // (2) Do the reallocation + copy:
    redfat_node_t newnode = redfat_node_malloc(size);
    if (newnode == NULL)
        return NULL;
    size_t copy_size = (size < node->size? size: node->size);
    libc_memmove(newnode->object, node->object, copy_size);
    redfat_node_free(node);
    return newnode;
}
extern void *redfat_realloc(void *ptr, size_t size)
{
    if (ptr == NULL)
        return redfat_malloc(size);

    redfat_node_t node = redfat_node(ptr);
    if (node == NULL)
        return redfat_fallback_realloc(ptr, size);

    redfat_node_t newnode = redfat_node_realloc(node, size);
    if (newnode == NULL)
    {
        void *newptr = redfat_fallback_malloc(size);
        if (newptr == NULL)
            return NULL;
        size_t copy_size = (size < node->size? size: node->size);
        libc_memmove(ptr, node->object, copy_size);
        redfat_node_free(node);
        return ptr;
    }

    REDFAT_DEBUG("realloc(%p, %zu) = %p [base=%p, size=%zu]\n",
        ptr, size, newnode->object, newnode, redfat_size(newnode));
    assert(redfat_size(newnode) > newnode->size + REDFAT_REDZONE_SIZE);
    return newnode->object;
}
extern void *realloc(void *ptr, size_t size) REDFAT_ALIAS("redfat_realloc");

/*
 * REDFAT posix_memalign()
 */
extern int redfat_posix_memalign(void **memptr, size_t align, size_t size)
{
    *memptr = NULL;
    if (align < sizeof(void *) || (align & (align - 1)) != 0)
        return EINVAL;
    if (align <= 16)
        *memptr = redfat_malloc(size);
    else
    {
        size_t nsize = size + align - 1;
        uint8_t *ptr = (uint8_t *)redfat_malloc(nsize);
        if (ptr == NULL)
            return ENOMEM;
        size_t offset = (uintptr_t)ptr % align;
        offset = (offset != 0? align - offset: offset);
        ptr += offset;
        *memptr = (void *)ptr;
    }
    return 0;
}
extern int posix_memalign(void **memptr, size_t align, size_t size)
    REDFAT_ALIAS("redfat_posix_memalign");

extern void *redfat_memalign(size_t align, size_t size)
{
    void *ptr;
    int err = redfat_posix_memalign(&ptr, align, size);
    if (err != 0)
    {
        errno = err;
        return NULL;
    }
    return ptr;
}
extern void *memalign(size_t align, size_t size)
    REDFAT_ALIAS("redfat_memalign");

extern void *redfat_aligned_alloc(size_t align, size_t size)
    REDFAT_ALIAS("redfat_memalign");
extern void *aligned_alloc(size_t align, size_t size)
    REDFAT_ALIAS("redfat_memalign");

extern void *redfat_valloc(size_t size)
{
    return redfat_memalign(REDFAT_PAGE_SIZE, size);
}
extern void *valloc(size_t size) REDFAT_ALIAS("redfat_valloc");

extern void *redfat_pvalloc(size_t size)
{
    return redfat_memalign(REDFAT_PAGE_SIZE,
        REDFAT_NUM_PAGES(size) * REDFAT_PAGE_SIZE);
}
extern void *pvalloc(size_t size) REDFAT_ALIAS("redfat_pvalloc");

/*
 * C++ new/delete.
 */
extern void *redfat__Znwm(size_t size)
{
    void *ptr = redfat_malloc(size);
    if (ptr != NULL)
        return ptr;
    if (libcpp_throw_bad_alloc != NULL)
        libcpp_throw_bad_alloc();
    redfat_error("failed to throw std::bad_alloc()");
}
extern void *redfat__Znam(size_t size) REDFAT_ALIAS("redfat__Znwm");
extern void *redfat__ZnwmRKSt9nothrow_t(size_t size)
    REDFAT_ALIAS("redfat_malloc");
extern void *redfat__ZnamRKSt9nothrow_t(size_t size)
    REDFAT_ALIAS("redfat_malloc");

extern void *_Znwm(size_t size) REDFAT_ALIAS("redfat__Znwm");
extern void *_Znam(size_t size) REDFAT_ALIAS("redfat__Znwm");
extern void *_ZnwmRKSt9nothrow_t(size_t size) REDFAT_ALIAS("redfat_malloc");
extern void *_ZnamRKSt9nothrow_t(size_t size) REDFAT_ALIAS("redfat_malloc");

extern void redfat__ZdlPv(void *ptr) REDFAT_ALIAS("redfat_free");
extern void redfat__ZdaPv(void *ptr) REDFAT_ALIAS("redfat_free");
extern void redfat__ZdaPvRKSt9nothrow_t(void *ptr) REDFAT_ALIAS("redfat_free");
extern void redfat__ZdlPvRKSt9nothrow_t(void *ptr) REDFAT_ALIAS("redfat_free");
extern void redfat__ZdaPvm(void *ptr, size_t size)
{
    size_t ptr_size = redfat_get_buffer_size(ptr);
    if (size != ptr_size)
        redfat_lib_error(ptr, size);
    free(ptr);
}
extern void redfat__ZdlPvm(void *ptr, size_t size)
    REDFAT_ALIAS("redfat__ZdaPvm");

extern void _ZdlPv(void *ptr) REDFAT_ALIAS("redfat_free");
extern void _ZdaPv(void *ptr) REDFAT_ALIAS("redfat_free");
extern void _ZdaPvRKSt9nothrow_t(void *ptr) REDFAT_ALIAS("redfat_free");
extern void _ZdlPvRKSt9nothrow_t(void *ptr) REDFAT_ALIAS("redfat_free");
extern void _ZdaPvm(void *ptr, size_t size) REDFAT_ALIAS("redfat__ZdaPvm");
extern void _ZdlPvm(void *ptr, size_t size) REDFAT_ALIAS("redfat__ZdaPvm");

extern void *redfat__ZnwmSt11align_val_t(size_t size, size_t align)
{
    void *ptr = redfat_memalign(align, size);
    if (ptr != NULL)
        return ptr;
    if (libcpp_throw_bad_alloc != NULL)
        libcpp_throw_bad_alloc();
    redfat_error("failed to throw std::bad_alloc()");
}
extern void *redfat__ZnamSt11align_val_t(size_t size, size_t align)
    REDFAT_ALIAS("redfat__ZnwmSt11align_val_t");
extern void *redfat__ZnwmSt11align_val_tRKSt9nothrow_t(size_t size,
    size_t align)
{
    return redfat_memalign(align, size);
}
extern void *redfat__ZnamSt11align_val_tRKSt9nothrow_t(size_t size,
    size_t align) REDFAT_ALIAS("redfat__ZnwmSt11align_val_tRKSt9nothrow_t");

extern void *_ZnwmSt11align_val_t(size_t size, size_t align)
    REDFAT_ALIAS("redfat__ZnwmSt11align_val_t");
extern void *_ZnamSt11align_val_t(size_t size, size_t align)
    REDFAT_ALIAS("redfat__ZnwmSt11align_val_t");
extern void *_ZnwmSt11align_val_tRKSt9nothrow_t(size_t size, size_t align)
    REDFAT_ALIAS("redfat__ZnwmSt11align_val_tRKSt9nothrow_t");
extern void *_ZnamSt11align_val_tRKSt9nothrow_t(size_t size, size_t align)
    REDFAT_ALIAS("redfat__ZnwmSt11align_val_tRKSt9nothrow_t");

extern void redfat__ZdlPvSt11align_val_t(void *ptr, size_t align)
    REDFAT_ALIAS("redfat__ZdlPv");
extern void redfat__ZdlPvmSt11align_val_t(void *ptr, size_t size,
    size_t align) REDFAT_ALIAS("redfat__ZdlPvm");
extern void redfat__ZdlPvSt11align_val_tRKSt9nothrow_t(void *ptr, size_t align)
    REDFAT_ALIAS("redfat__ZdlPv");
extern void redfat__ZdaPvSt11align_val_t(void *ptr, size_t align)
    REDFAT_ALIAS("redfat__ZdaPv");
extern void redfat__ZdaPvmSt11align_val_t(void *ptr, size_t size, size_t align)
    REDFAT_ALIAS("redfat__ZdaPvm");
extern void redfat__ZdaPvSt11align_val_tRKSt9nothrow_t(void *ptr, size_t align)
    REDFAT_ALIAS("redfat__ZdaPv");

extern void _ZdlPvSt11align_val_t(void *ptr, size_t align)
    REDFAT_ALIAS("redfat__ZdlPv");
extern void _ZdlPvmSt11align_val_t(void *ptr, size_t size,
    size_t align) REDFAT_ALIAS("redfat__ZdlPvm");
extern void _ZdlPvSt11align_val_tRKSt9nothrow_t(void *ptr, size_t align)
    REDFAT_ALIAS("redfat__ZdlPv");
extern void _ZdaPvSt11align_val_t(void *ptr, size_t align)
    REDFAT_ALIAS("redfat__ZdaPv");
extern void _ZdaPvmSt11align_val_t(void *ptr, size_t size, size_t align)
    REDFAT_ALIAS("redfat__ZdaPvm");
extern void _ZdaPvSt11align_val_tRKSt9nothrow_t(void *ptr, size_t align)
    REDFAT_ALIAS("redfat__ZdaPv");

/*
 * REDFAT strdup()
 */
extern char *redfat_strdup(const char *str)
{
    size_t len = redfat_strlen(str);
    char *str2 = (char *)malloc(len+1);
    libc_memmove(str2, str, len+1);
    return str2;
}
extern char *redfat___strdup(const char *str) REDFAT_ALIAS("redfat_strdup");
extern char *strdup(const char *str) REDFAT_ALIAS("redfat_strdup");
extern char *__strdup(const char *str) REDFAT_ALIAS("redfat_strdup");

/*
 * REDFAT strndup()
 */
extern char *redfat_strndup(const char *str, size_t n)
{
    size_t len = redfat_strnlen(str, n);
    char *str2 = (char *)malloc(len+1);
    libc_memmove(str2, str, len);
    str2[len] = '\0';
    return str2;
}
extern char *redfat___strndup(const char *str, size_t n)
    REDFAT_ALIAS("redfat_strndup");
extern char *strndup(const char *str, size_t n) REDFAT_ALIAS("redfat_strndup");
extern char *__strndup(const char *str, size_t n)
    REDFAT_ALIAS("redfat_strndup");

/*
 * REDFAT malloc_usable_size()
 */
extern size_t redfat_malloc_usable_size(void *ptr)
{
    size_t size = redfat_get_buffer_size(ptr);
    if (size < SIZE_MAX)
        return size;
    else
        return libc_malloc_usable_size(ptr);
}
extern size_t malloc_usable_size(void *ptr)
    REDFAT_ALIAS("redfat_malloc_usable_size");

/*
 * pthread_create() wrappers.
 */
typedef void *(*redfat_start_routine_t)(void *);
struct redfat_pthread_s
{
    redfat_start_routine_t start_routine;
    void *arg;
};
typedef struct redfat_pthread_s *redfat_pthread_t;
static void *redfat_start_routine(void *arg_0)
{
    redfat_pthread_t data = (redfat_pthread_t)arg_0;
    void *arg = data->arg;
    redfat_start_routine_t start_routine = data->start_routine;
    free(data);

    redfat_thread_start((void *)redfat_local);

    void *result;
    pthread_cleanup_push(redfat_thread_exit, redfat_local);
    result = start_routine(arg);
    pthread_cleanup_pop(/*execute=*/true);

    return result;
}

/*
 * We initialize the TLS by intercepting pthread_create().  Other methods,
 * such as __cxa_thread_atexit_impl(), lead to deadlocks with dlopen().
 */
int pthread_create(pthread_t *thread, const pthread_attr_t *attr,
    redfat_start_routine_t start_routine, void *arg)
{
    redfat_pthread_t data =
        (redfat_pthread_t)malloc(sizeof(struct redfat_pthread_s));      
    if (data == NULL)
        redfat_error("failed to allocated pthread data: %s", strerror(errno));
    data->arg = arg;
    data->start_routine = start_routine;
    int r = libc_pthread_create(thread, attr, redfat_start_routine, data);
    if (r != 0)
        free(data);
    return r;
}

