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

#include <ctype.h>
#include <link.h>

static REDFAT_DATA REDFAT_ALIGNED(4096) void *redfat_libc_funcs[512] = {NULL};

enum
{
    REDFAT_MEMSET_IDX,
    REDFAT_MEMMOVE_IDX,
    REDFAT_MEMCMP_IDX,
    REDFAT_MEMCHR_IDX,
    REDFAT_MEMRCHR_IDX,
    REDFAT_STRNLEN_IDX,
    REDFAT_STRNCMP_IDX,
    REDFAT_STRNCASECMP_IDX,
    REDFAT_STRRCHR_IDX,
    REDFAT_MALLOC_IDX,
    REDFAT_REALLOC_IDX,
    REDFAT_FREE_IDX,
    REDFAT_MALLOC_USABLE_SIZE_IDX,
    REDFAT_PTHREAD_CREATE_IDX,
    REDFAT_THROW_BAD_ALLOC_IDX,
};

static REDFAT_DATA const char *redfat_libc_names[] =
{
    [REDFAT_MEMSET_IDX]             = "memset",
    [REDFAT_MEMMOVE_IDX]            = "memmove",
    [REDFAT_MEMCMP_IDX]             = "memcmp",
    [REDFAT_MEMCHR_IDX]             = "memchr",
    [REDFAT_MEMRCHR_IDX]            = "memrchr",
    [REDFAT_STRNLEN_IDX]            = "strnlen",
    [REDFAT_STRNCMP_IDX]            = "strncmp",
    [REDFAT_STRNCASECMP_IDX]        = "strncasecmp",
    [REDFAT_STRRCHR_IDX]            = "strrchr",
    [REDFAT_MALLOC_IDX]             = "malloc",
    [REDFAT_REALLOC_IDX]            = "realloc",
    [REDFAT_FREE_IDX]               = "free",
    [REDFAT_MALLOC_USABLE_SIZE_IDX] = "malloc_usable_size",
    [REDFAT_PTHREAD_CREATE_IDX]     = "pthread_create",
    [REDFAT_THROW_BAD_ALLOC_IDX]    = "_ZSt17__throw_bad_allocv",
};

#define libc_memset                                                     \
    ((void *(*)(void *, int, size_t))                                   \
        redfat_libc_funcs[REDFAT_MEMSET_IDX])
#define libc_memmove                                                    \
    ((void *(*)(void *, const void *, size_t))                          \
        redfat_libc_funcs[REDFAT_MEMMOVE_IDX])
#define libc_memcmp                                                     \
    ((int (*)(const void *, const void *, size_t))                      \
        redfat_libc_funcs[REDFAT_MEMCMP_IDX])
#define libc_memchr                                                     \
    ((void *(*)(const void *, int, size_t))                             \
        redfat_libc_funcs[REDFAT_MEMCHR_IDX])
#define libc_memrchr                                                    \
    ((void *(*)(const void *, int, size_t))                             \
        redfat_libc_funcs[REDFAT_MEMRCHR_IDX])
#define libc_strnlen                                                    \
    ((size_t (*)(const char *, size_t))                                 \
        redfat_libc_funcs[REDFAT_STRNLEN_IDX])
#define libc_strncmp                                                    \
    ((int (*)(const char *, const char *, size_t))                      \
        redfat_libc_funcs[REDFAT_STRNCMP_IDX])
#define libc_strncasecmp                                                \
    ((int (*)(const char *, const char *, size_t))                      \
        redfat_libc_funcs[REDFAT_STRNCASECMP_IDX])
#define libc_strrchr                                                    \
    ((char *(*)(const char *, int))                                     \
        redfat_libc_funcs[REDFAT_STRRCHR_IDX])
#define libc_malloc                                                     \
    ((void *(*)(size_t))                                                \
        redfat_libc_funcs[REDFAT_MALLOC_IDX])
#define libc_realloc                                                    \
    ((void *(*)(void *, size_t))                                        \
        redfat_libc_funcs[REDFAT_REALLOC_IDX])
#define libc_free                                                       \
    ((void (*)(void *))                                                 \
        redfat_libc_funcs[REDFAT_FREE_IDX])
#define libc_malloc_usable_size                                         \
    ((size_t (*)(void *))                                               \
        redfat_libc_funcs[REDFAT_MALLOC_USABLE_SIZE_IDX])
#define libc_pthread_create                                             \
    ((int (*)(pthread_t *, const pthread_attr_t *, void *(*)(void *),   \
            void *))                                                    \
        redfat_libc_funcs[REDFAT_PTHREAD_CREATE_IDX])
#define libcpp_throw_bad_alloc                                          \
    ((void (*)(void))                                                   \
        redfat_libc_funcs[REDFAT_THROW_BAD_ALLOC_IDX])

/*
 * Lookup a symbol.
 */
static const Elf64_Sym *redfat_lookup_sym(const void *hshtab_0,
    const Elf64_Sym *symtab, const char *strtab, const char *name)
{
	struct hshtab_s
	{
	    uint32_t nbuckets;
	    uint32_t symoffset;
	    uint32_t bloomsz;
	    uint32_t bloomshft;
	    uint8_t data[];
	};

    uint32_t h = 5381;
    for (int i = 0; name[i]; i++)
        h = (h << 5) + h + name[i];

    const struct hshtab_s *hshtab =
        (const struct hshtab_s *)hshtab_0;

    const uint32_t *buckets =
        (const uint32_t *)(hshtab->data + hshtab->bloomsz * sizeof(uint64_t));
    const uint32_t *chain = buckets + hshtab->nbuckets;

    uint32_t idx = buckets[h % hshtab->nbuckets];
    if (idx < hshtab->symoffset)
        return NULL;
    for (; ; idx++)
    {
        const char* entry = strtab + symtab[idx].st_name;
        const uint32_t hh = chain[idx - hshtab->symoffset];
        if ((hh | 0x1) == (h | 0x1))
        {
            bool match = true;
            for (size_t i = 0; match; i++)
            {
                match = (name[i] == entry[i]);
                if (name[i] == '\0')
                    break;
            }
            if (match)
                return symtab + idx;
        }
        if ((hh & 0x1) != 0)
            return NULL;
    }
}

/*
 * Lookup a symbol address.
 */
static void *redfat_lookup_sym_addr(struct link_map *l, const void *hshtab,
    const Elf64_Sym *symtab, const char *strtab, const char *name)
{
    const Elf64_Sym *sym = redfat_lookup_sym(hshtab, symtab, strtab, name);
    if (sym == NULL)
        return NULL;
    void *addr = (void *)(l->l_addr + sym->st_value);
    switch (ELF64_ST_TYPE(sym->st_info))
    {
        case STT_FUNC:
            break;
        case STT_GNU_IFUNC:
            addr = ((void *(*)(void))addr)();
            break;
        default:
            redfat_error("unknown type for symbol \"%s\"", name);
    }
    return addr;
}

/*
 * Initialize the libc functions.
 *
 * NOTE: We do not use dlsym() since it seems to break under this use-case.
 *       The problem is that dlsym() itself will call intercepted libc
 *       functions, like memset, resulting in a circular dependency.
 *       To solve this, we effectively re-implement a specialized dlsym().
 */
static void redfat_libc_init(void)
{
    struct r_debug *debug = &_r_debug;
    struct link_map *link_map = debug->r_map;
    struct link_map *l      = NULL;
    const void *hshtab      = NULL;
    const Elf64_Sym *symtab = NULL;
    const char *strtab      = NULL;
    for (l = link_map; l != NULL; l = l->l_next)
    {
        const Elf64_Dyn *dynamic = l->l_ld;
        if (dynamic == NULL || dynamic == _DYNAMIC)
            continue;
        hshtab = NULL;
        symtab = NULL;
        strtab = NULL;
        for (size_t i = 0; dynamic[i].d_tag != DT_NULL; i++)
        {
            switch (dynamic[i].d_tag)
            {
                case DT_STRTAB:
                    strtab = (const char *)dynamic[i].d_un.d_ptr;
                    break;
                case DT_SYMTAB:
                    symtab = (const Elf64_Sym *)dynamic[i].d_un.d_ptr;
                    break;
                case DT_GNU_HASH:
                    hshtab = (const void *)dynamic[i].d_un.d_ptr;
                    break;
                default:
                    continue;
            }
        }
        if (hshtab == NULL || symtab == NULL || strtab == NULL)
            continue;
        if ((intptr_t)hshtab <= UINT32_MAX || (intptr_t)symtab <= UINT32_MAX ||
                (intptr_t)strtab <= UINT32_MAX)
            continue;
        if (redfat_lookup_sym(hshtab, symtab, strtab, "malloc") != NULL)
        {
            for (size_t i = 0;
                i < sizeof(redfat_libc_names) / sizeof(redfat_libc_names[0]);
                i++)
            {
                if (redfat_libc_funcs[i] != NULL)
                    continue;
                redfat_libc_funcs[i] = redfat_lookup_sym_addr(l, hshtab,
                    symtab, strtab, redfat_libc_names[i]);
            }
        }
        void *ptr = redfat_lookup_sym_addr(l, hshtab, symtab, strtab,
                redfat_libc_names[REDFAT_THROW_BAD_ALLOC_IDX]);
        if (ptr != NULL)
            redfat_libc_funcs[REDFAT_THROW_BAD_ALLOC_IDX] = ptr;
        ptr = redfat_lookup_sym_addr(l, hshtab, symtab, strtab,
                redfat_libc_names[REDFAT_PTHREAD_CREATE_IDX]);
        if (ptr != NULL)
            redfat_libc_funcs[REDFAT_PTHREAD_CREATE_IDX] = ptr;
    }
    for (size_t i = 0;
            i < sizeof(redfat_libc_names) / sizeof(redfat_libc_names[0]); i++)
    {
        if (i == REDFAT_THROW_BAD_ALLOC_IDX)
            continue;
        if (redfat_libc_funcs[i] == NULL)
            redfat_error("failed to find libc function \"%s\"",
                redfat_libc_names[i]);
    }

    if (mprotect(redfat_libc_funcs, sizeof(redfat_libc_funcs), PROT_READ) != 0)
        redfat_error("failed to protect libc function table");
}

/*
 * Get the (accurate) buffer size.
 */
static size_t redfat_get_buffer_size(const void *ptr_0)
{
    if (redfat_option_profile_mode)
        __sync_fetch_and_add(&redfat_profile_checks, 1);
    if (!redfat_malloc_inited)
    {
        redfat_init();
        return SIZE_MAX;    // No malloc = not low fat
    }

    const uint8_t *base = (const uint8_t *)redfat_base(ptr_0);
    if (base == NULL)
        return SIZE_MAX;
    if (redfat_option_profile_mode)
        __sync_fetch_and_add(&redfat_profile_redfat_checks, 1);
    const uint8_t *ptr = (const uint8_t *)ptr_0;
    if (ptr - base < REDFAT_REDZONE_SIZE)
        return 0;
    size_t offset = (ptr - base - REDFAT_REDZONE_SIZE);
    size_t size = *(const size_t *)base;
    uint64_t canary = *((const uint64_t *)base + 1);
    if (canary != redfat_canary)
        return 0;
    if (size >= redfat_size(base) - REDFAT_REDZONE_SIZE)
        return 0;
    if (offset >= size)
        return 0;
    if (redfat_option_canary_mode)
    {
        const uint64_t *canary_ptr =
            (const uint64_t *)(base + REDFAT_REDZONE_SIZE + size);
        canary =
            (size > redfat_size(ptr)-REDFAT_REDZONE_SIZE-sizeof(uint64_t)?
                0x0: *canary_ptr);
        if (canary != redfat_canary)
            return 0;
    }
    return size - offset;
}

/*
 * Report an error.
 */
static REDFAT_NOINLINE REDFAT_NORETURN void redfat_lib_error_2(
    const char *func, const void *ptr_0, size_t access)
{
    char prefix[] = "redfat_";
    if (libc_strncmp(func, prefix, sizeof(prefix)-1) == 0)
        func += sizeof(prefix)-1;
    const uint8_t *ptr = (const uint8_t *)ptr_0;
    const uint8_t *base = (const uint8_t *)redfat_base(ptr);
    if (base == NULL)
        redfat_error("invalid-pointer error detected!\n"
            "\tfunction = %s()\n"
            "\tpointer  = %p",
            func, ptr);
    else if (ptr - base >= REDFAT_REDZONE_SIZE)
    {
        size_t size = *(size_t *)base;
        uint64_t canary = *((const uint64_t *)base + 1);
        if (canary != redfat_canary)
            redfat_error("heap-canary-corruption (LB) error detected!\n"
                "\tfunction = %s()\n"
                "\tpointer  = %p\n"
                "\texpected = 0x%.16llx\n"
                "\tfound    = 0x%.16llx",
                func, ptr, redfat_canary, canary);
        else if (size == 0)
            redfat_error("use-after-free error detected!\n"
                "\tfunction = %s()\n"
                "\tpointer  = %p",
                func, ptr);
        else if (size >= redfat_size(base) - REDFAT_REDZONE_SIZE)
            redfat_error("size-metadata-corruption error detected!\n"
                "\tfunction = %s()\n"
                "\tpointer  = %p\n"
                "\tmetadata = %zu\n"
                "\tmax      = %zu",
                func, ptr, size, redfat_size(base) - REDFAT_REDZONE_SIZE);
        else if (redfat_option_canary_mode)
        {
            const uint64_t *canary_ptr =
                (const uint64_t *)(base + REDFAT_REDZONE_SIZE + size);
            canary =
                (size > redfat_size(ptr)-REDFAT_REDZONE_SIZE-sizeof(uint64_t)?
                    0x0: *canary_ptr);
            if (canary != redfat_canary)
                redfat_error("heap-canary-corruption (UB) error detected!\n"
                    "\tfunction = %s()\n"
                    "\tpointer  = %p\n"
                    "\texpected = 0x%.16llx\n"
                    "\tfound    = 0x%.16llx",
                    func, ptr, redfat_canary, canary);
        }
    }
    size_t size = redfat_get_buffer_size(ptr_0);
    redfat_error("out-of-bounds (buffer-overflow) error detected!\n"
        "\tfunction      = %s()\n"
        "\tbuffer.ptr    = %p\n"
        "\tbuffer.size   = %zu\n"
        "\tbuffer.access = %zu",
        func, ptr, size, access);
}
#define redfat_lib_error(ptr, access)                                       \
    redfat_lib_error_2(__func__, (ptr), (access))

/*
 * Verify a string.
 */
static inline size_t redfat_check_string_2(const char *func, const char *str)
{
    size_t str_size = redfat_get_buffer_size(str);
    size_t str_len  = libc_strnlen(str, str_size);
    if (str_len >= str_size)
        redfat_lib_error_2(func, str, str_len+1);
    return str_len;
}
#define redfat_check_string(str)                                            \
    redfat_check_string_2(__func__, (str))

/*
 * REDFAT memset
 */
extern void *redfat___memset_chk(void *dst, int c, size_t n, size_t dst_size)
{
    if (dst_size < n)
        redfat_lib_error(dst, n);
    return libc_memset(dst, c, n);
}
extern void *redfat_memset(void *dst, int c, size_t n)
{
    size_t dst_size = redfat_get_buffer_size(dst);
    return redfat___memset_chk(dst, c, n, dst_size);
}

/*
 * REDFAT memmove
 */
extern void *redfat___memmove_chk(void *dst, const void *src, size_t n,
    size_t dst_size)
{
    size_t src_size = redfat_get_buffer_size(src);
    if (src_size < n)
        redfat_lib_error(src, n);
    if (dst_size < n)
        redfat_lib_error(dst, n);
    return libc_memmove(dst, src, n);
}
extern void *redfat_memmove(void *dst, const void *src, size_t n)
{
    size_t dst_size = redfat_get_buffer_size(dst);
    return redfat___memmove_chk(dst, src, n, dst_size);
}
extern void *redfat_memcpy(void *dst, const void *src, size_t n)
    REDFAT_ALIAS("redfat_memmove");
extern void *redfat___memcpy_chk(void *dst, const void *src, size_t n,
    size_t dst_size) REDFAT_ALIAS("redfat___memmove_chk");

/*
 * REDFAT memcmp
 */
extern int redfat_memcmp(const void *src1, const void *src2, size_t n)
{
    size_t src1_size = redfat_get_buffer_size(src1);
    size_t src2_size = redfat_get_buffer_size(src2);
    size_t m = n;
    m = (m < src1_size? m: src1_size);
    m = (m < src2_size? m: src2_size);
    int cmp = libc_memcmp(src1, src2, m);
    if (cmp != 0)
        return cmp;
    if (m < n)
        redfat_lib_error((src1_size < src2_size? src1: src2), m+1);
    return 0;
}

/*
 * REDFAT memchr
 */
extern void *redfat_memchr(const void *src, int c, size_t n)
{
    size_t src_size = redfat_get_buffer_size(src);
    size_t m = n;
    m = (m < src_size? m: src_size);
    void *r = libc_memchr(src, c, m);
    if (r != NULL)
        return r;
    if (m < n)
        redfat_lib_error(src, m+1);
    return NULL;
}
extern void *redfat_memrchr(const void *src, int c, size_t n)
{
    size_t src_size = redfat_get_buffer_size(src);
    if (src_size < n)
        redfat_lib_error(src, n);
    return libc_memrchr(src, c, n);
}

/*
 * REDFAT strlen
 */
extern size_t redfat_strnlen(const char *src, size_t n)
{
    size_t src_size = redfat_get_buffer_size(src);
    size_t m = n;
    m = (m < src_size? m: src_size);
    size_t len = libc_strnlen(src, m);
    if (len < m)
        return len;
    if (m < n)
        redfat_lib_error(src, m+1);
    return m;
}
extern size_t redfat_strlen(const char *src)
{
    return redfat_strnlen(src, SIZE_MAX);
}

/*
 * REDFAT strcmp
 */
extern int redfat_strncmp(const char *src1, const char *src2, size_t n)
{
    size_t src1_size = redfat_get_buffer_size(src1);
    size_t src2_size = redfat_get_buffer_size(src2);
    size_t m = n;
    m = (m < src1_size? m: src1_size);
    m = (m < src2_size? m: src2_size);
    int cmp = libc_strncmp(src1, src2, m);
    if (cmp != 0)
        return cmp;
    if (m == n)
        return 0;
    if (libc_strnlen(src1, m) == m)
        redfat_lib_error((src1_size < src2_size? src1: src2), m+1);
    return 0;
}
extern int redfat_strcmp(const char *src1, const char *src2)
{
    return redfat_strncmp(src1, src2, SIZE_MAX);
}
extern int redfat_strncasecmp(const char *src1, const char *src2, size_t n)
{
    size_t src1_size = redfat_get_buffer_size(src1);
    size_t src2_size = redfat_get_buffer_size(src2);
    size_t m = n;
    m = (m < src1_size? m: src1_size); 
    m = (m < src2_size? m: src2_size); 
    int cmp = libc_strncasecmp(src1, src2, m);
    if (cmp != 0)
        return cmp;
    if (m == n)
        return 0;
    if (libc_strnlen(src1, m) == m)
        redfat_lib_error((src1_size < src2_size? src1: src2), m+1);
    return 0;
}
extern int redfat_strcasecmp(const char *src1, const char *src2)
{
    return redfat_strncasecmp(src1, src2, SIZE_MAX);
}

/*
 * REDFAT strcat
 */
extern char *redfat___strncat_chk(char *dst, const char *src, size_t n,
    size_t dst_size)
{
    size_t dst_len  = libc_strnlen(dst, dst_size);
    if (dst_len >= dst_size)
        redfat_lib_error(dst, dst_len+1);
    size_t src_size = redfat_get_buffer_size(src);
    size_t m = n;
    m = (m < src_size? m: src_size);
    size_t src_len = libc_strnlen(src, m);
    if (src_len == m && m < n)
        redfat_lib_error(src, m+1);
    if (dst_size < dst_len + src_len + 1)
        redfat_lib_error(dst, dst_len + src_len + 1);
    libc_memmove(dst + dst_len, src, src_len);
    dst[dst_len + src_len] = '\0';
    return dst;
}
extern char *redfat___strcat_chk(char *dst, const char *src, size_t dst_size)
{
    return redfat___strncat_chk(dst, src, SIZE_MAX, dst_size);
}
extern char *redfat_strncat(char *dst, const char *src, size_t n)
{
    size_t dst_size = redfat_get_buffer_size(dst);
    return redfat___strncat_chk(dst, src, n, dst_size);
}
extern char *redfat_strcat(char *dst, const char *src)
{
    size_t dst_size = redfat_get_buffer_size(dst);
    return redfat___strcat_chk(dst, src, dst_size);
}

/*
 * REDFAT strcpy
 */
extern char *redfat___strncpy_chk(char *dst, const char *src, size_t n,
    size_t dst_size)
{
    if (dst_size < n)
        redfat_lib_error(dst, n);
    size_t src_size = redfat_get_buffer_size(src);
    size_t m = n;
    m = (m < src_size? m: src_size);
    size_t src_len = libc_strnlen(src, m);
    if (src_len == m && m < n)
        redfat_lib_error(src, m+1);
    libc_memmove(dst, src, src_len);
    libc_memset(dst + src_len, 0x0, n - src_len);
    return dst;
}
extern char *redfat___strcpy_chk(char *dst, const char *src, size_t dst_size)
{
    size_t src_len = redfat_check_string(src);
    if (dst_size < src_len+1)
        redfat_lib_error(dst, src_len+1);
    libc_memmove(dst, src, src_len+1);
    return dst;
}
extern char *redfat_strncpy(char *dst, const char *src, size_t n)
{
    size_t dst_size = redfat_get_buffer_size(dst);
    return redfat___strncpy_chk(dst, src, n, dst_size);
}
extern char *redfat_strcpy(char *dst, const char *src)
{
    size_t dst_size = redfat_get_buffer_size(dst);
    return redfat___strcpy_chk(dst, src, dst_size);
}

/*
 * REDFAT strchr
 */
extern char *redfat_strchr(const char *src, int c)
{
    size_t src_size = redfat_get_buffer_size(src);
    for (size_t i = 0; ; i++)
    {
        if (src_size < i)
            redfat_lib_error(src, i);
        if ((int)src[i] == c)
            return (char *)(src + i);
        if (src[i] == '\0')
            return NULL;
    }
}
extern char *redfat_strrchr(const char *src, int c)
{
    redfat_check_string(src);
    return libc_strrchr(src, c);
}
extern char *redfat_strchrnul(const char *src, int c)
{
    size_t src_size = redfat_get_buffer_size(src);
    for (size_t i = 0; ; i++)
    {
        if (src_size < i)
            redfat_lib_error(src, i);
        if ((int)src[i] == c || src[i] == '\0')
            return (char *)(src + i);
    }
}

/*
 * REDFAT strstr
 */
extern char *redfat_strstr(const char *haystack, const char *needle)
{
    size_t haystack_size = redfat_get_buffer_size(haystack);
    size_t needle_size   = redfat_get_buffer_size(needle);
    for (size_t i = 0; ; i++)
    {
        if (haystack_size < i)
            redfat_lib_error(haystack, i);
        if (haystack[i] == '\0')
            return NULL;
        for (size_t j = 0; ; j++)
        {
            if (needle_size < j)
                redfat_lib_error(needle, j);
            if (needle[j] == '\0')
                return (char *)(haystack + i);
            if (haystack_size < i + j)
                redfat_lib_error(haystack, i + j);
            if (haystack[i + j] != needle[j])
                break;
        }
    }
}
extern char *redfat_strcasestr(const char *haystack, const char *needle)
{
    size_t haystack_size = redfat_get_buffer_size(haystack);
    size_t needle_size   = redfat_get_buffer_size(needle);
    for (size_t i = 0; ; i++)
    {
        if (haystack_size < i)
            redfat_lib_error(haystack, i);
        if (haystack[i] == '\0')
            return NULL;
        for (size_t j = 0; ; j++)
        {
            if (needle_size < j)
                redfat_lib_error(needle, j);
            if (needle[j] == '\0')
                return (char *)(haystack + i);
            if (haystack_size < i + j)
                redfat_lib_error(haystack, i + j);
            if (tolower(haystack[i + j]) != tolower(needle[j]))
                break;
        }
    }
}

/*
 * LIBC interceptions.
 */
extern void *memset(void *dst, int c, size_t n) REDFAT_ALIAS("redfat_memset");
extern void *__memset_chk(void *dst, int c, size_t n, size_t dst_len)
    REDFAT_ALIAS("redfat___memset_chk");
extern void *memcpy(void *dst, const void *src, size_t n)
    REDFAT_ALIAS("redfat_memcpy");
extern void *memmove(void *dst, const void *src, size_t n)
    REDFAT_ALIAS("redfat_memmove");
extern void *__memcpy_chk(void *dst, const void *src, size_t n,
    size_t dst_size) REDFAT_ALIAS("redfat___memcpy_chk");
extern void *__memmove_chk(void *dst, const void *src, size_t n,
    size_t dst_size) REDFAT_ALIAS("redfat___memmove_chk");
extern int memcmp(const void *src1, const void *src2, size_t n)
    REDFAT_ALIAS("redfat_memcmp");
extern void *memchr(const void *src, int c, size_t n)
    REDFAT_ALIAS("redfat_memchr");
extern void *memrchr(const void *src, int c, size_t n)
    REDFAT_ALIAS("redfat_memrchr");
extern size_t strlen(const char *src) REDFAT_ALIAS("redfat_strlen");
extern size_t strnlen(const char *src, size_t maxlen)
    REDFAT_ALIAS("redfat_strnlen");
extern int strcmp(const char *src1, const char *src2)
    REDFAT_ALIAS("redfat_strcmp");
extern int strncmp(const char *src1, const char *src2, size_t n)
    REDFAT_ALIAS("redfat_strncmp");
extern int strcasecmp(const char *src1, const char *src2)
    REDFAT_ALIAS("redfat_strcasecmp");
extern int strncasecmp(const char *src1, const char *src2, size_t n)
    REDFAT_ALIAS("redfat_strncasecmp");
extern char *strcat(char *dst, const char *src) REDFAT_ALIAS("redfat_strcat");
extern char *strncat(char *dst, const char *src, size_t n)
    REDFAT_ALIAS("redfat_strncat");
extern char *__strncat_chk(char *dst, const char *src, size_t n,
    size_t dst_size) REDFAT_ALIAS("redfat___strncat_chk");
extern char *__strcat_chk(char *dst, const char *src, size_t dst_size)
    REDFAT_ALIAS("redfat___strcat_chk");
extern char *strncpy(char *dst, const char *src, size_t n)
    REDFAT_ALIAS("redfat_strncpy");
extern char *strcpy(char *dst, const char *src) REDFAT_ALIAS("redfat_strcpy");
extern char *__strncpy_chk(char *dst, const char *src, size_t n,
    size_t dst_size) REDFAT_ALIAS("redfat___strncpy_chk");
extern char *__strcpy_chk(char *dst, const char *src, size_t dst_size)
    REDFAT_ALIAS("redfat___strcpy_chk");
extern char *strchr(const char *src, int c) REDFAT_ALIAS("redfat_strchr");
extern char *strrchr(const char *src, int c) REDFAT_ALIAS("redfat_strrchr");
extern char *strchrnul(const char *src, int c)
    REDFAT_ALIAS("redfat_strchrnul");
extern char *strstr(const char *haystack, const char *needle)
    REDFAT_ALIAS("redfat_strstr");
extern char *strcasestr(const char *haystack, const char *needle)
    REDFAT_ALIAS("redfat_strcasestr");

