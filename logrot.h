/*	$Id: logrot.h,v 1.6 1997/03/18 06:45:06 lukem Exp $	*/

/*
 * Copyright 1997, 1998 Luke Mewburn <lukem@netbsd.org>.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 * 	This product includes software developed by Luke Mewburn.
 * 4. The name of the author may not be used to endorse or promote products
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

#ifndef _LOGROT_H
#define _LOGROT_H

#include "config.h"

#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <ctype.h>
#include <errno.h>
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#include <signal.h>
#if defined __STDC__ || defined HAVE_STDARG_H
#include <stdarg.h>
#else
#include <varargs.h>
#endif
#include <stdio.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#else
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# ifdef HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif


#if defined(GZIP)
#ifndef COMPRESS_PROG
#define COMPRESS_PROG	GZIP
#endif
#ifndef COMPRESS_EXT
#define COMPRESS_EXT	".gz"
#endif
#endif

#ifndef COMPRESS_PROG
#error "gzip not available; please supply COMPRESS_PROG and COMPRESS_EXT"
#endif

#ifndef DEFAULT_PIDFILE
#define DEFAULT_PIDFILE	PIDFILE
#endif

#ifndef DEFAULT_FORMAT
#define DEFAULT_FORMAT	"%f.%y%m%d"
#endif

#ifndef DEFAULT_SIGNAL
#define DEFAULT_SIGNAL	SIGHUP
#endif

#ifndef DEFAULT_WAIT
#define DEFAULT_WAIT	5
#endif

#ifndef PATH_BSHELL
#define PATH_BSHELL	"/bin/sh"
#endif

#ifndef MAXFD
#define MAXFD sysconf(_SC_OPEN_MAX)
#endif

char	*progname;		/* name of program (for error messages) */

char   *filter_log(const char *, const char *, const char *, const char *,
		const char *);
pid_t	parse_pid(const char *);
char   *parse_rotate_fmt(const char *, const char *, const char *, time_t);
int	parse_sig(const char *);
int	parse_wait(const char *);
void	process_log(const char *, const char *);
char   *rotate_log(const char *, pid_t, int, int);
void	splitpath(const char *, char **, char **);
char   *xstrdup(const char *);


#ifndef HAVE_MKSTEMP
int	mkstemp(char *);
#endif
#ifndef HAVE_ERR
void	err(int eval, const char *fmt, ...);
void	errx(int eval, const char *fmt, ...);
void	warn(const char *fmt, ...);
void	warnx(const char *fmt, ...);
#endif

#endif /* _LOGROT_H */
