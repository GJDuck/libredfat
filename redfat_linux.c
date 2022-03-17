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

#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>

extern REDFAT_NOINLINE const char *redfat_color_escape_code(FILE *stream,
    bool red)
{
    // Simply assumes ANSI compatible terminal rather than create ncurses
    // dependency.  Who still uses non-ANSI terminals anyway?
    int err = errno;
    int r = isatty(fileno(stream));
    errno = err;
    if (!r)
        return "";
    else
        return (red? "\33[31m": "\33[0m");
}

static void redfat_random_page(void *buf)
{
    int r = syscall(SYS_getrandom, buf, REDFAT_PAGE_SIZE, 0);
    if (r != REDFAT_PAGE_SIZE)
	    redfat_error("failed to get %zu random bytes", REDFAT_PAGE_SIZE);
}

#include <execinfo.h>
static REDFAT_NOINLINE void redfat_backtrace(void)
{
	size_t MAX_TRACE = 256;
	void *trace[MAX_TRACE];
	int len = backtrace(trace, sizeof(trace) / sizeof(void *));
	char **trace_strs = backtrace_symbols(trace, len);
	for (int i = 0; i < len; i++)
	    fprintf(stderr, "%d: %s\n", i, trace_strs[i]);
	if (len == 0 || len == sizeof(trace) / sizeof(void *))
	    fprintf(stderr, "...\n");
}

