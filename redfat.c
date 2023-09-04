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

#include <errno.h>
#include <string.h>

#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define REDFAT_PAGE_SIZE        4096

#define REDFAT_CONSTRUCTOR      __attribute__((__constructor__(10102)))
#define REDFAT_DESTRUCTOR       __attribute__((__destructor__(10102)))
#define REDFAT_NOINLINE         __attribute__((__noinline__))
#define REDFAT_NORETURN         __attribute__((__noreturn__))
#define REDFAT_CONST            __attribute__((__const__))
#define REDFAT_ALIAS(name)      __attribute__((__alias__(name)))
#define REDFAT_ALIGNED(n)       __attribute__((__aligned__(n)))
#define REDFAT_DATA             /* EMPTY */
#define REDFAT_CPUID(a, c, ax, bx, cx, dx)                                  \
    __asm__ __volatile__ ("cpuid" : "=a" (ax), "=b" (bx), "=c" (cx),        \
        "=d" (dx) : "a" (a), "c" (c))

#define REDFAT_SIZES            _REDFAT_SIZES
#define REDFAT_MAGICS           _REDFAT_MAGICS

void redfat_init(void);
static REDFAT_NOINLINE void redfat_rand(void *buf, size_t len);
static REDFAT_CONST void *redfat_region(size_t idx);

#include "redfat_config.c"
#include "redfat.h"

static REDFAT_DATA uint8_t *redfat_seed = NULL;
static REDFAT_DATA size_t redfat_seed_pos = REDFAT_PAGE_SIZE;
static REDFAT_DATA bool redfat_malloc_inited = false;

static REDFAT_DATA bool     redfat_option_profile_mode = false;
#ifdef REDFAT_ZERO
#define redfat_option_zero_mode     REDFAT_ZERO
#else
static REDFAT_DATA bool     redfat_option_zero_mode    = false;
#endif
#ifdef REDFAT_CANARY
#define redfat_option_canary_mode   REDFAT_CANARY
#else
static REDFAT_DATA bool     redfat_option_canary_mode  = false;
#endif
#ifdef REDFAT_ASLR
#define redfat_option_aslr_mode     REDFAT_ASLR
#else
static REDFAT_DATA bool     redfat_option_aslr_mode    = false;
#endif
#ifdef REDFAT_QUARANTINE
#define redfat_option_quarantine    REDFAT_QUARANTINE
#else
static REDFAT_DATA uint32_t redfat_option_quarantine   = 0;
#endif
static REDFAT_DATA int redfat_option_signal            = 0;
static REDFAT_DATA bool redfat_option_reserve          = false;
static REDFAT_DATA uint32_t redfat_option_test_rate    = 0;

static REDFAT_DATA uint64_t redfat_canary = 0x0;

static REDFAT_DATA size_t redfat_profile_alloc_count   = 0;
static REDFAT_DATA size_t redfat_profile_alloc_bytes   = 0;
static REDFAT_DATA size_t redfat_profile_checks        = 0;
static REDFAT_DATA size_t redfat_profile_redfat_checks = 0;

#include "redfat_linux.c"
#include "redfat_threads.c"
#include "redfat_memops.c"
#include "redfat_malloc.c"

static REDFAT_DATA redfat_mutex_t redfat_print_mutex;
static REDFAT_DATA redfat_mutex_t redfat_rand_mutex;
static REDFAT_DATA size_t redfat_num_messages = 0;

/*
 * CSPRNG
 */
static void redfat_rand(void *buf0, size_t len)
{
    uint8_t *buf = (uint8_t *)buf0;

    redfat_mutex_lock(&redfat_rand_mutex);
    while (len > 0)
    {
        if (redfat_seed_pos >= REDFAT_PAGE_SIZE)
        {
            redfat_random_page(redfat_seed);
            redfat_seed_pos = 0;
        }
        *buf = redfat_seed[redfat_seed_pos];
        redfat_seed[redfat_seed_pos] = 0;
        redfat_seed_pos++;
        len--;
        buf++;
    }
    redfat_mutex_unlock(&redfat_rand_mutex);
}

/*
 * Abort.
 */
static REDFAT_NORETURN void redfat_abort(void)
{
    if (redfat_option_signal >= 1 && redfat_option_signal <= 31)
        raise(redfat_option_signal);
    abort();
}

/*
 * Print the redfat banner.
 */
static REDFAT_NOINLINE void redfat_print_banner(void)
{
    fprintf(stderr, "%s"
        "_|_|_|    _|_|_|_|  _|_|_|        _|_|              _|\n"
        "_|    _|  _|        _|    _|    _|        _|_|_|  _|_|_|_|\n"
        "_|_|_|    _|_|_|    _|    _|  _|_|_|_|  _|    _|    _|\n"
        "_|    _|  _|        _|    _|    _|      _|    _|    _|\n"
        "_|    _|  _|_|_|_|  _|_|_|      _|        _|_|_|      _|_|%s\n"
        "\n",
        redfat_color_escape_code(stderr, true),
        redfat_color_escape_code(stderr, false));
}

/*
 * Print an error or warning.
 */
static REDFAT_NOINLINE void redfat_message(const char *format, bool err,
    va_list ap)
{
    redfat_mutex_lock(&redfat_print_mutex);

    // (1) Print the error:
    redfat_print_banner();
    fprintf(stderr, "%sREDFAT %s%s: ",
        redfat_color_escape_code(stderr, true),
        (err? "ERROR": "WARNING"),
        redfat_color_escape_code(stderr, false));
    vfprintf(stderr, format, ap);
    fputc('\n', stderr);

    // (2) Dump the stack:
    if (redfat_malloc_inited)
        redfat_backtrace();

    redfat_num_messages++;
    redfat_mutex_unlock(&redfat_print_mutex);
}

/*
 * Print an error and exit.
 */
REDFAT_NOINLINE REDFAT_NORETURN void redfat_error(const char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    redfat_message(format, /*err=*/true, ap);
    va_end(ap);
    redfat_abort();
}

/*
 * Print a warning.
 */
REDFAT_NOINLINE void redfat_warning(const char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    redfat_message(format, /*err=*/false, ap);
    va_end(ap);
}

/*
 * Get an option value.
 */
static ssize_t redfat_get_option(const char *option, ssize_t lb, ssize_t ub,
    ssize_t _default)
{
    const char *val = getenv(option);
    if (val == NULL)
        return _default;
    if (strcmp(val, "true") == 0)
        return 1;
    if (strcmp(val, "false") == 0)
        return 0;
    errno = 0;
    char *end = NULL;
    ssize_t r = strtoll(val, &end, 0);
    if ((r == 0 && errno != 0) || end == NULL || end[0] != '\0')
        redfat_error("failed to parse value \"%s\" for option %s",
            val, option);
    if (r < lb || r > ub)
        redfat_error("failed to parse value for option %s; "
            "value %zd is outside the expected range %zd..%zd",
            option, r, lb, ub);
    return r;
}

/*
 * dl_iterate_phdr() callback.
 */
struct redfat_callback_data_s
{
    void *addr;
    const Elf64_Phdr *phdr;
    size_t phnum;
};
static int redfat_dl_iterate_phdr_callback(struct dl_phdr_info *info,
    size_t size, void *data_0)
{
    struct redfat_callback_data_s *data = data_0;
    if (data->addr != (void *)info->dlpi_addr)
        return 0;
    data->phdr  = info->dlpi_phdr;
    data->phnum = info->dlpi_phnum;
    return /*stop=*/1;
}

/*
 * Setup the REDFAT environment.
 */
void REDFAT_CONSTRUCTOR redfat_init(void)
{
    static bool redfat_inited = false;
    if (redfat_inited)
        return;
    redfat_inited = true;

    redfat_libc_init();

    redfat_mutex_init(&redfat_print_mutex);
    redfat_mutex_init(&redfat_rand_mutex);

    // Options:
    redfat_option_profile_mode = redfat_get_option("REDFAT_PROFILE", 0, 1,
        false);
#ifndef REDFAT_ZERO
    redfat_option_zero_mode = redfat_get_option("REDFAT_ZERO", 0, 1, false);
#endif
#ifndef REDFAT_CANARY
    redfat_option_canary_mode = redfat_get_option("REDFAT_CANARY", 0, 1,
        false);
#endif
#ifndef REDFAT_QUARANTINE
    redfat_option_quarantine = redfat_get_option("REDFAT_QUARANTINE", 0,
        UINT32_MAX, 0);
#endif
#ifndef REDFAT_ASLR 
    redfat_option_aslr_mode = redfat_get_option("REDFAT_ASLR", 0, 1, true);
#endif
    redfat_option_test_rate = redfat_get_option("REDFAT_TEST",
        0, UINT16_MAX, 0);
    bool redfat_option_cpu_check = redfat_get_option("REDFAT_CPU_CHECK", 0, 1,
        true);
    redfat_option_signal  = redfat_get_option("REDFAT_SIGNAL", 1, 31, 0);
    redfat_option_reserve = redfat_get_option("REDFAT_RESERVE", 0, 1, false);

    // Basic sanity checks:
    if (sizeof(void *) != sizeof(uint64_t))
        redfat_error("incompatible architecture (not x86-64)");
    if (sysconf(_SC_PAGESIZE) != REDFAT_PAGE_SIZE)
        redfat_error("incompatible system page size (expected %u; got %ld)",
            REDFAT_PAGE_SIZE, sysconf(_SC_PAGESIZE));
    if (redfat_option_cpu_check)
    {
        uint32_t eax, ebx, ecx, edx;
        REDFAT_CPUID(7, 0, eax, ebx, ecx, edx);
        if (((ebx >> 3) & 1) == 0 || ((ebx >> 8) & 1) == 0)
            redfat_error("incompatible architecture (no BMI/BMI2 support)\n"
                "              (define REDFAT_CPU_CHECK=0 to disable this "
                    "check)");
    }
 
    // Random seed memory:
    redfat_seed = (uint8_t *)mmap(NULL, REDFAT_PAGE_SIZE,
        PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if ((void *)redfat_seed == MAP_FAILED)
        redfat_error("failed to allocate random seed: %s", strerror(errno));

    // Init REDFAT_SIZES and REDFAT_MAGICS
    struct r_debug *debug = &_r_debug;
    struct link_map *l, *link_map = debug->r_map;
    for (l = link_map; l != NULL && l->l_ld != _DYNAMIC; l = l->l_next)
        ;
    if (l == NULL)
        redfat_error("failed to find link_map entry");
    const void *hshtab      = NULL;
    const Elf64_Sym *symtab = NULL;
    const char *strtab      = NULL;
    for (size_t i = 0; _DYNAMIC[i].d_tag != DT_NULL; i++)
    {
        switch (_DYNAMIC[i].d_tag)
        {
            case DT_STRTAB:
                strtab = (const char *)_DYNAMIC[i].d_un.d_ptr;
                break;
            case DT_SYMTAB:
                symtab = (const Elf64_Sym *)_DYNAMIC[i].d_un.d_ptr;
                break;
            case DT_GNU_HASH:
                hshtab = (const void *)_DYNAMIC[i].d_un.d_ptr;
                break;
            default:
                continue;
        }
    }
    if (hshtab == NULL || symtab == NULL || strtab == NULL)
        redfat_error("failed to find DT_STRTAB/DT_SYMTAB/DT_GNU_HASH");
    const Elf64_Sym *sizes_sym = redfat_lookup_sym(hshtab, symtab, strtab,
        "__REDFAT_SIZES");
    const Elf64_Sym *sizes_max_sym = redfat_lookup_sym(hshtab, symtab, strtab,
        "__REDFAT_SIZES_MAX");
    const Elf64_Sym *magics_sym = redfat_lookup_sym(hshtab, symtab, strtab,
        "__REDFAT_MAGICS");
    if (sizes_sym == NULL || sizes_max_sym == NULL || magics_sym == NULL)
        redfat_error("failed to find __REDFAT_SIZES/__REDFAT_SIZES_MAX/"
            "__REDFAT_MAGICS symbols");
    struct redfat_callback_data_s data;
    data.addr = (void *)l->l_addr;
    if (dl_iterate_phdr(redfat_dl_iterate_phdr_callback, &data) == 0)
        redfat_error("failed to find ELF PHDRs");
    off_t sizes_offset = -1, sizes_max_offset = -1, magics_offset = -1;
    const Elf64_Phdr *phdr = data.phdr;
    size_t phnum = data.phnum;
    for (size_t i = 0; i < phnum; i++)
    {
        if (phdr[i].p_type != PT_LOAD)
            continue;
        if (sizes_sym->st_value >= phdr[i].p_vaddr &&
                sizes_sym->st_value <= phdr[i].p_vaddr + phdr[i].p_filesz)
            sizes_offset = phdr[i].p_offset +
                (sizes_sym->st_value - phdr[i].p_vaddr);
        if (sizes_max_sym->st_value >= phdr[i].p_vaddr &&
                sizes_max_sym->st_value <= phdr[i].p_vaddr + phdr[i].p_filesz)
            sizes_max_offset = phdr[i].p_offset +
                (sizes_max_sym->st_value - phdr[i].p_vaddr);
        if (magics_sym->st_value >= phdr[i].p_vaddr &&
                magics_sym->st_value <= phdr[i].p_vaddr + phdr[i].p_filesz)
            magics_offset = phdr[i].p_offset +
                (magics_sym->st_value - phdr[i].p_vaddr);
    }
    if (sizes_offset < 0 || sizes_max_offset < 0 || magics_offset < 0)
        redfat_error("failed to find __REDFAT_SIZES/__REDFAT_SIZES_MAX/"
            "__REDFAT_MAGICS offsets");
    const char *name = l->l_name;
    if (name == NULL || name[0] == '\0')
        name = "/proc/self/exe";    // Binary is the main exe
    int fd = open(name, O_RDONLY);
    if (fd < 0)
        redfat_error("failed to open \"%s\" for reading: %s", name,
            strerror(errno));

    {
        // Create REDFAT_SIZES:
        void *ptr = mmap((void *)REDFAT_SIZES, REDFAT_PAGE_SIZE, PROT_READ,
            MAP_PRIVATE | MAP_FIXED | MAP_POPULATE, fd, sizes_offset);
        if (ptr != (void *)REDFAT_SIZES)
        {
            mmap_error:
            redfat_error("failed to mmap memory: %s", strerror(errno));
        }

        size_t total_pages = (sizeof(uint64_t) *
            (/*max_addr=*/0x1000000000000ull / REDFAT_REGION_SIZE)) /
                REDFAT_PAGE_SIZE;
        void *start = (uint8_t *)REDFAT_SIZES + REDFAT_PAGE_SIZE;
        void *end   = (uint8_t *)REDFAT_SIZES +
            (total_pages - 1) * REDFAT_PAGE_SIZE;
        while (start < end)
        {
            ptr = mmap(start, REDFAT_PAGE_SIZE, PROT_READ,
                MAP_PRIVATE | MAP_FIXED | MAP_NORESERVE, fd, sizes_max_offset);
            if (ptr != start)
                goto mmap_error;
            start = (uint8_t *)start + REDFAT_PAGE_SIZE;
        }

        // Create REDFAT_MAGICS:
        ptr = mmap((void *)REDFAT_MAGICS, REDFAT_PAGE_SIZE, PROT_READ,
            MAP_PRIVATE | MAP_FIXED | MAP_POPULATE, fd, magics_offset);
        if (ptr != (void *)REDFAT_MAGICS)
            goto mmap_error;
        if (close(fd) < 0)
            redfat_error("failed to close file: %s", strerror(errno));
        start = (uint8_t *)REDFAT_MAGICS + REDFAT_PAGE_SIZE;
        end   = (uint8_t *)REDFAT_MAGICS + (total_pages - 1) * REDFAT_PAGE_SIZE;
        ptr = mmap(start, (uint8_t *)end - (uint8_t *)start, PROT_READ,
            MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED | MAP_NORESERVE, -1, 0);
        if (ptr != start)
            goto mmap_error;
    }

    // Initialize malloc()
    redfat_malloc_init();
    redfat_malloc_inited = true;
}

void REDFAT_DESTRUCTOR redfat_fini(void)
{
    if (!redfat_option_profile_mode)
        return;
    fprintf(stderr, "total.allocs   = %zu (%zubytes)\n",
        redfat_profile_alloc_count, redfat_profile_alloc_bytes);
    fprintf(stderr, "library.checks = %zu\n", redfat_profile_checks);
    fprintf(stderr, "        (heap) = %zu\n\n", redfat_profile_redfat_checks);
}

extern inline size_t redfat_index(const void *ptr);
extern inline size_t redfat_size(const void *ptr);
extern inline size_t redfat_buffer_size(const void *ptr);

static REDFAT_CONST void *redfat_region(size_t idx)
{
    return (void *)(idx * REDFAT_REGION_SIZE);
}

extern REDFAT_CONST bool redfat_is_ptr(const void *ptr)
{
    size_t idx = redfat_index(ptr);
    return (idx - 1) <= REDFAT_NUM_REGIONS;
}

