/*
 * Copyright 1997-1999, 2005 Luke Mewburn <luke@mewburn.net>.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
 * TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#if !defined(_LOGROT_H)
#define _LOGROT_H

#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>
#ifdef STAT_MACROS_BROKEN
#undef S_ISREG
#undef S_ISDIR
#define S_ISREG(mode) (((mode)&S_IFMT) == S_IFREG)
#define S_ISDIR(mode) (((mode)&S_IFMT) == S_IFDIR)
#endif

#include <ctype.h>
#if defined(HAVE_ERR_H)
#include <err.h>
#endif
#include <errno.h>
#if defined(HAVE_FCNTL_H)
#include <fcntl.h>
#endif
#include <getopt.h>
#include <signal.h>
#if defined(__STDC__) || defined(HAVE_STDARG_H)
#include <stdarg.h>
#else
#include <varargs.h>
#endif
#include <stdbool.h>
#include <stdio.h>
#if defined(HAVE_STDLIB_H)
#include <stdlib.h>
#endif
#if defined(HAVE_STRING_H)
#include <string.h>
#elif defined(HAVE_STRINGS_H)
#include <strings.h>
#endif
#ifdef HAVE_STRINGLIST_H
#include <stringlist.h>
#else
#include "stringlist.h"
#endif
#include <unistd.h>

#if defined(HAVE_SYS_WAIT_H)
#include <sys/wait.h>
#endif
#if !defined(WEXITSTATUS)
#define WEXITSTATUS(stat_val) ((unsigned)(stat_val) >> 8)
#endif
#if !defined(WIFEXITED)
#define WIFEXITED(stat_val) (((stat_val)&255) == 0)
#endif

#if defined(TIME_WITH_SYS_TIME)
#include <sys/time.h>
#include <time.h>
#else
#if defined(HAVE_SYS_TIME_H)
#include <sys/time.h>
#else
#include <time.h>
#endif
#endif

#if defined(GZIP)
#if !defined(COMPRESS_PROG)
#define COMPRESS_PROG GZIP
#endif
#if !defined(COMPRESS_EXT)
#define COMPRESS_EXT ".gz"
#endif
#endif

#if !defined(COMPRESS_PROG)
#error "gzip not available; please supply COMPRESS_PROG and COMPRESS_EXT"
#endif

#if !defined(DEFAULT_PIDFILE)
#define DEFAULT_PIDFILE PIDFILE
#endif

#if !defined(DEFAULT_FORMAT)
#define DEFAULT_FORMAT "-%Y%m%d"
#endif

#if !defined(DEFAULT_SIGNAL)
#define DEFAULT_SIGNAL SIGHUP
#endif

#if !defined(DEFAULT_WAIT)
#define DEFAULT_WAIT 5
#endif

#if !defined(PATH_BSHELL)
#define PATH_BSHELL "/bin/sh"
#endif

#if defined(HAVE_SYSCONF)
#define MAXFD sysconf(_SC_OPEN_MAX)
#else
#define MAXFD OPEN_MAX
#endif

#if !defined(HAVE_STRERROR)
char* strerror(int);
#endif

#if !defined(HAVE_MKSTEMP)
int mkstemp(char*);
#endif

#if !defined(HAVE_ERR)
void err(int eval, const char* fmt, ...);
void errx(int eval, const char* fmt, ...);
void warn(const char* fmt, ...);
void warnx(const char* fmt, ...);
#endif

#endif /* _LOGROT_H */
