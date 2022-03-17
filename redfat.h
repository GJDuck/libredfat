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

#ifndef __REDFAT_H
#define __REDFAT_H

#ifndef REDFAT_NO_INCLUDE
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#endif

#ifdef __cplusplus 
extern "C"
{
#endif

#define _REDFAT_CONST      __attribute__((__const__))
#define _REDFAT_NORETURN   __attribute__((__noreturn__))
#define _REDFAT_MALLOC     __attribute__((__malloc__))
#define _REDFAT_INLINE     __attribute__((__always_inline__))

#define REDFAT_OOB_ERROR_READ               0
#define REDFAT_OOB_ERROR_WRITE              1
#define REDFAT_OOB_ERROR_MEMCPY             2
#define REDFAT_OOB_ERROR_MEMSET             3
#define REDFAT_OOB_ERROR_STRDUP             4
#define REDFAT_OOB_ERROR_ESCAPE_CALL        5
#define REDFAT_OOB_ERROR_ESCAPE_RETURN      6
#define REDFAT_OOB_ERROR_ESCAPE_STORE       7
#define REDFAT_OOB_ERROR_ESCAPE_PTR2INT     8
#define REDFAT_OOB_ERROR_ESCAPE_INSERT      9
#define REDFAT_OOB_ERROR_UNKNOWN            0xFF

#define REDFAT_REDZONE_SIZE                 16

#include <redfat_config.h>

/*
 * Tests if the given pointer is low-fat or not.
 */
extern _REDFAT_CONST bool redfat_is_ptr(const void *_ptr);

/*
 * Return the region index of the given pointer.
 */
static inline _REDFAT_INLINE size_t redfat_index(const void *_ptr)
{
    return (uintptr_t)_ptr / _REDFAT_REGION_SIZE;
}

/*
 * Return the (allocation) size of the object pointed to by `_ptr', measured 
 * from the object's base address.  If the size is unknown then this function
 * returns SIZE_MAX.
 */
static inline _REDFAT_CONST _REDFAT_INLINE size_t redfat_size(const void *_ptr)
{
    size_t _idx = redfat_index(_ptr);
    return _REDFAT_SIZES[_idx];
}

#ifndef REDFAT_IS_POW2
/*
 * Return the "object index" of the object pointed to by `_ptr', defined as
 * objidx = _ptr / redfat_size(_ptr).  Not implemented in POW2-mode.
 */
static inline _REDFAT_CONST _REDFAT_INLINE size_t redfat_objidx(
        const void *_ptr)
{
    size_t _idx = redfat_index(_ptr);
    unsigned __int128 _tmp = (unsigned __int128)_REDFAT_MAGICS[_idx] *
        (unsigned __int128)(uintptr_t)_ptr;
    size_t _objidx = (size_t)(_tmp >> 64);
    return _objidx;
}
#endif  /* REDFAT_IS_POW2 */

/*
 * Return the base-pointer of the object pointed to by `_ptr'.  If the base
 * pointer is unknown then this functon returns NULL.
 */
static inline _REDFAT_CONST _REDFAT_INLINE void *redfat_base(const void *_ptr)
{
    size_t _idx = redfat_index(_ptr);
#ifndef REDFAT_IS_POW2
    size_t _objidx = redfat_objidx(_ptr);
    return (void *)(_objidx * _REDFAT_SIZES[_idx]);
#else   /* REDFAT_IS_POW2 */
    return (void *)((uintptr_t)_ptr & _REDFAT_MAGICS[_idx]);
#endif  /* REDFAT_IS_POW2 */
}

/*
 * Return the low-fat magic number for `_ptr'.
 */
static inline _REDFAT_CONST _REDFAT_INLINE size_t redfat_magic(const void *_ptr)
{
    size_t _idx = redfat_index(_ptr);
    return _REDFAT_MAGICS[_idx];
}

/*
 * Return the (allocation) size of the buffer pointed to by `_ptr', measured
 * from `_ptr' itself.  If the size is unknown then this function returns
 * (SIZE_MAX - (uintptr_t)_ptr).
 */
static inline _REDFAT_CONST _REDFAT_INLINE size_t redfat_buffer_size(
    const void *_ptr)
{
    return redfat_size(_ptr) -
        ((const uint8_t *)(_ptr) - (const uint8_t *)redfat_base(_ptr));
}

/*
 * Safe replacement malloc().
 */
extern _REDFAT_MALLOC void *redfat_malloc(size_t _size);

/*
 * Safe replacement free().
 */
extern void redfat_free(void *_ptr);

/*
 * Safe replacement realloc().
 */
extern void *redfat_realloc(void *_ptr, size_t _size);

/*
 * Safe replacement calloc().
 */
extern _REDFAT_MALLOC void *redfat_calloc(size_t _nmemb, size_t _size);

/*
 * Safe replacement posix_memalign().
 */
extern int redfat_posix_memalign(void **memptr, size_t align, size_t size);

/*
 * Safe replacement memalign().
 */
extern _REDFAT_MALLOC void *redfat_memalign(size_t _align, size_t _size);

/*
 * Safe replacement aligned_alloc().
 */
extern _REDFAT_MALLOC void *redfat_aligned_alloc(size_t _align, size_t _size);

/*
 * Safe replacement valloc().
 */
extern _REDFAT_MALLOC void *redfat_valloc(size_t _size);

/*
 * Safe replacment pvalloc().
 */
extern _REDFAT_MALLOC void *redfat_pvalloc(size_t _size);

/*
 * Safe replacement strdup().
 */
extern _REDFAT_MALLOC char *redfat_strdup(const char *_str);

/*
 * Safe replacement strndup().
 */
extern _REDFAT_MALLOC char *redfat_strndup(const char *_str, size_t _n);

/*
 * Print an error and exit.
 */
extern _REDFAT_NORETURN void redfat_error(const char *format, ...);

/*
 * Print a warning.
 */
extern void redfat_warning(const char *format, ...);

#ifdef __cplusplus 
}
#endif

#endif      /* __REDFAT_H */
