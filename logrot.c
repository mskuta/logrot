/*	$Id: logrot.c,v 1.11 1997/04/02 06:28:29 lukem Exp $	*/

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

#if !defined(lint)
static char rcsid[] = "$Id: logrot.c,v 1.11 1997/04/02 06:28:29 lukem Exp $";
#endif /* !lint */

#include "logrot.h"


/*
 * failure exit value:
 *	1 = temp file exists
 *	2 = no temp file
 */
int ecode;


/*
 * usage --
 *	Display a usage message and exit
 */
void
usage()
{
	fprintf(stderr,
"Usage: %s\t[-c] [-C compressor] [-d destdir] [-f filter] [-B preprocessor]\n"
"\t\t[-F postprocessor] [-p pidfile] [-r rotate_format] [-s sig]\n"
"\t\t[-w wait] [-X compress_extension] file\n",
	    progname);
	exit(ecode);
} /* usage */

/*
 * main --
 *	Main entry point
 */
int
main(int argc, char *argv[])
{
	int	 compress;		/* non-zero if compression required */
	char	*compress_prog;		/* compression program to use */
	char	*compress_ext;		/* extension of compressed files */
	char	*destdir;		/* destination of rotated logfile */
	char	*filter_prog;		/* in-line filter program */
	char	*log;			/* log file to rotate */
	char	*pidfile;		/* pidfile containing pid to signal */
	char	*preprocess_prog;	/* pre compression filter program */
	char	*postprocess_prog;	/* post compression filter program */
	char	*rotate_fmt;		/* format of rotated logfile name */

	pid_t	 pid;			/* pid to signal */
	int	 sig;			/* signal to send to pid */
	int	 wait;			/* waittime after signal until rotate */

	time_t	 now;
	int	 ch;
	char	*origlog, *rotlog, *finallog;

	(void) umask(077);		/* be safe when creating temp files */

	ecode = 2;			/* exit val for no temp file */

	splitpath(argv[0], &origlog, &progname);
	free(origlog);

	compress =		0;
	compress_prog =		COMPRESS_PROG;
	compress_ext =		COMPRESS_EXT;
	destdir =		NULL;
	filter_prog =		NULL;
	pidfile =		DEFAULT_PIDFILE;
	postprocess_prog =	NULL;
	preprocess_prog =	NULL;
	rotate_fmt =		DEFAULT_FORMAT;
	pid =			0;
	sig =			DEFAULT_SIGNAL;
	wait =			DEFAULT_WAIT;

	while ((ch = getopt(argc, argv, "B:cC:d:f:F:p:r:s:w:X:")) != -1) {
		switch(ch) {
		case 'B':
			preprocess_prog = optarg;
			break;
		case 'c':
			compress++;
			break;
		case 'C':
			compress_prog = optarg;
			break;
		case 'd':
			destdir = optarg;
			break;
		case 'f':
			filter_prog = optarg;
			break;
		case 'F':
			postprocess_prog = optarg;
			break;
		case 'p':
			pidfile = optarg;
			break;
		case 'r':
			rotate_fmt = optarg;
			break;
		case 's':
			sig = parse_sig(optarg);
			break;
		case 'w':
			wait = parse_wait(optarg);
			break;
		case 'X':
			compress_ext = optarg;
			break;
		case '?':
		default:
			usage();
			/* NOTREACHED */
		}
	}
	if (optind != argc - 1)
		usage();
	log = argv[argc - 1];

	if (pidfile && pidfile[0] && sig)
		pid = parse_pid(pidfile);

	(void) time(&now);
	rotlog = parse_rotate_fmt(rotate_fmt, destdir, log, now);
	origlog = rotate_log(log, pid, sig, wait);
	if (preprocess_prog && preprocess_prog[0])
		process_log(origlog, preprocess_prog);
	finallog = filter_log(origlog, rotlog, filter_prog,
				compress ? compress_prog : NULL, compress_ext);
	if (postprocess_prog && postprocess_prog[0])
		process_log(finallog, postprocess_prog);

	free(finallog);
	free(origlog);
	free(rotlog);
	exit(0);
} /* main */


/*
 * filter_log --
 *	Filter origlog into rotlog, passing through
 *	filter_prog then compress_prog if necessary.
 *	If compress_prog != NULL, compress_ext is appended
 *	to rotlog to generate the resultant filename.
 *	Sets the permissions and modification time of rotlog
 *	to those of origlog, and then unlinks origlog if an
 *	error didn't occur in the filtering.
 *	Returns a pointer to a malloc(3)ed string containing the
 *	resultant filename.
 */
char *
filter_log(const char *origlog, const char *rotlog, const char *filter_prog,
	const char *compress_prog, const char *compress_ext)
{
	struct stat stbuf;
	char	outfile[MAXPATHLEN];
	int	infd, outfd, pipefd[2], ispipe, junkfd;
	int	filter_pid, compress_pid, rstat;

	if ((strlen(rotlog) +
	    (compress_prog != NULL ? strlen(compress_ext) : 0) + 1) >
	    sizeof(outfile))
		errx(ecode, "rotated filename would be too long");
	strcpy(outfile, rotlog);
	if (compress_prog != NULL)
		strcat(outfile, compress_ext);

	if ((infd = open(origlog, O_RDONLY)) == -1)
		err(ecode, "can't open '%s'", origlog);

	if ((outfd = open(outfile, O_WRONLY | O_CREAT | O_EXCL, 0700)) == -1)
		err(ecode, "can't open '%s' for writing", outfile);

	filter_pid = -1;
	compress_pid = -1;
	ispipe = 0;

	if (filter_prog && compress_prog) {
		if (pipe(pipefd) == -1)
			err(ecode, "can't create pipe");
		ispipe = 1;
	}

	if (filter_prog) {
		switch (filter_pid = fork()) {
		case -1:
			err(ecode, "can't fork");
		case 0:
			if (dup2(infd, fileno(stdin)) == -1)
				err(ecode, "can't dup2 filter stdin");
			if (dup2(ispipe ? pipefd[0] : outfd,
			    fileno(stdout)) == -1)
				err(ecode, "can't dup2 filter stdout");
			for (junkfd = 3 ; junkfd < MAXFD; junkfd++)
				close(junkfd);
			execl(PATH_BSHELL, "sh", "-c", filter_prog, NULL);
			err(ecode, "can't exec sh to run '%s'", filter_prog);
		default:
			if (ispipe)
				close(pipefd[0]);
		}
	}

	if (compress_prog) {
		switch (compress_pid = fork()) {
		case -1:
			err(ecode, "can't fork");
		case 0:
			if (dup2(ispipe ? pipefd[1] : infd,
			    fileno(stdin)) == -1)
				err(ecode, "can't dup2 compress stdin");
			if (dup2(outfd, fileno(stdout)) == -1)
				err(ecode, "can't dup2 compress stdout");
			for (junkfd = 3 ; junkfd < MAXFD; junkfd++)
				close(junkfd);
			execl(PATH_BSHELL, "sh", "-c", compress_prog, NULL);
			err(ecode, "can't exec sh to run '%s'", compress_prog);
		default:
			if (ispipe)
				close(pipefd[1]);
		}
	}

			/*
			 * direct copy required
			 */
	if (filter_pid == -1 && compress_pid == -1) {
		char	xferbuf[BUFSIZ], *tmp;
		size_t	in, out;

		while ((in = read(infd, xferbuf, sizeof(xferbuf))) > 0) {
			tmp = xferbuf;
			while ((out = write(outfd, tmp, in)) > 0) {
				tmp += out;
				in -= out;
			}
			if (out == -1)
				err(ecode, "writing '%s'", outfile);
		}
		if (in == -1)
			err(ecode, "reading '%s'", origlog);

			/*
			 * filtering via process(es) occurring
			 */
	} else while (filter_pid != -1 || compress_pid != -1) {
			/*
			 * XXX:	differentiate between child being stopped
			 *	with SIGSTOP/SIGTSTP, and child exiting ok.
			 */
		if ((filter_pid != -1) &&
		    (waitpid(filter_pid, &rstat, WNOHANG) != 0)) {
			if (WIFEXITED(rstat) != 0) {
				if (WEXITSTATUS(rstat) != 0)
					errx(ecode, "'%s' exited with %d",
					    filter_prog, WEXITSTATUS(rstat));
			} else if (WIFSIGNALED(rstat) != 0) {
				errx(ecode, "'%s' exited due to signal %d",
				    filter_prog, WTERMSIG(rstat));
			} else {
				errx(ecode, "'%s' returned status %d - why?",
				    filter_prog, rstat);
			}
			filter_pid = -1;
		}
		if ((compress_pid != -1) &&
		    (waitpid(compress_pid, &rstat, WNOHANG) != 0)) {
			if (WIFEXITED(rstat) != 0) {
				if (WEXITSTATUS(rstat) != 0)
					errx(ecode, "'%s' exited with %d",
					    compress_prog, WEXITSTATUS(rstat));
			} else if (WIFSIGNALED(rstat) != 0) {
				errx(ecode, "'%s' exited due to signal %d",
				    compress_prog, WTERMSIG(rstat));
			} else {
				errx(ecode, "'%s' returned status %d - why?",
				    compress_prog, rstat);
			}
			compress_pid = -1;
		}
		sleep(1);
	}

	if (fstat(infd, &stbuf) == -1)
		err(ecode, "can't stat '%s'", outfile);
	if (fchmod(outfd, stbuf.st_mode) == -1)
		err(ecode, "can't fchmod '%s' to %o", outfile,
		    (int)stbuf.st_mode);
	if (fchown(outfd, stbuf.st_uid, stbuf.st_gid) == -1)
		err(ecode, "can't fchown '%s' to %d,%d", outfile,
		    (int)stbuf.st_uid, (int)stbuf.st_gid);
	close(infd);
	close(outfd);
	if (unlink(origlog) == -1)
		err(ecode, "can't unlink '%s'", origlog);
	ecode = 2;	/* temp file gone; set exit code to indicate this */

	return (xstrdup(outfile));
} /* filter_log */


/*
 * parse_pid --
 *	Determine pid of process from pidfile.
 *	The first word of the pidfile will be used as the pid
 */
pid_t
parse_pid(const char *pidfile)
{
	FILE   *pf;
	char	buf[BUFSIZ], *p;
	pid_t	pid;

	if ((pf = fopen(pidfile, "r")) == NULL)
		err(ecode, "can't open '%s'", pidfile);
	pid = 0;
	if (fgets(buf, sizeof(buf), pf) != NULL) {
		p = buf;
		while (*p && isdigit(*p))
			p++;
		if (*p == '\0' || isspace(*p)) {
			*p = '\0';
			pid = atoi(buf);
		}
	}
	fclose(pf);
	if (pid == 0)
		errx(ecode, "can't parse pid from '%s'", pidfile);

	if (kill(pid, 0) == -1)
		errx(ecode, "can't send test signal 0 to pid %d", (int)pid);

	return (pid);
} /* parse_pid */


/*
 * parse_rotate_fmt --
 *	Parse the rotate format and build a target filename.
 *	Returns a pointer to a malloc(3)ed string containing the
 *	temporary name of the target filename.
 */
char *
parse_rotate_fmt(const char *fmt, const char *dir, const char *log, time_t now)
{
	struct stat	 stbuf;
	char		 buf[MAXPATHLEN];
	char		*bufend;
	char		*logdir, *logbase;
	const char	*from;
	char		*to;
	char		*junk1, junk2[4];
	struct tm	*tmnow;

	tmnow = localtime(&now);
	if (strlen(log) + (dir ? strlen(dir) : 0) + 3 > sizeof(buf))
		errx(ecode, "format '%s' is too long", fmt);
	splitpath(log, &logdir, &logbase);

	bufend = buf + sizeof(buf) - 1;

	memset(buf, 0, sizeof(buf) - 1);
	buf[0] = '\0';
	if (dir == NULL)		/* default target log dir `file.d' */
		sprintf(buf, "%s/%s.d", logdir, logbase);
	else if (dir[0] == '/')		/* fully qualified target log dir */
		sprintf(buf, "%s", dir);
	else				/* specific log dir */
		sprintf(buf, "%s/%s", logdir, dir);
	to = buf + strlen(buf);
	if (*to != '/')
		strcat(to++, "/");

	for (from = fmt; *from; from++) {
		if (to > bufend)
			errx(ecode, "format '%s' is too long", fmt);
		if (*from != '%') {
			*to++ = *from;
			continue;
		}
		from++;
		switch (*from) {
		case '\0':
			errx(ecode, "%% format requires a specifier");
		case '%':
			*to++ = *from;
			break;
		case 'f':
			junk1 = logbase;
			while (*junk1 && to <= bufend)
				*to++ = *junk1++;
			if (*junk1)
				errx(ecode, "%%%c in format '%s' is too long",
				    *from, fmt);
			break;
		case 'y':
		case 'Y':
		case 'm':
		case 'd':
		case 'H':
		case 'M':
		case 'S':
			sprintf(junk2, "%%%c", *from);
			to += strftime(to, bufend - to, junk2, tmnow);
			break;
		default:
			errx(ecode, "%%%c not supported in rotate_fmt", *from);
		}
	}

	if (stat(buf, &stbuf) == -1) {
		if (errno != ENOENT)
			err(ecode, "can't stat %s", buf);
	} else
		errx(ecode, "%s already exists", buf);

	free(logdir);
	free(logbase);
	return (xstrdup(buf));
} /* parse_rotate_fmt */


/*
 * parse_sig --
 *	Parse the given string for a signal name or number.
 */
int
parse_sig(const char *signame)
{
	struct sig_list {
		int	num;
		char   *name;
	} sigs[] = {
		{ SIGHUP,	"HUP",	},
		{ SIGINT,	"INT",	},
		{ SIGQUIT,	"QUIT",	},
		{ SIGTERM,	"TERM",	},
		{ SIGUSR1,	"USR1",	},
		{ SIGUSR2,	"USR2",	},
		{ -1,		NULL,	},
	};

	int	sig;

	sig = 0;
	if (isdigit(*signame)) {
		const char *p;

		p = signame;
		while (*p && isdigit(*p))
			p++;
		if (*p != '\0')
			errx(ecode, "invalid signal '%s'", signame);
		sig = atoi(signame);
	} else {
		int	i;

		for (i = 0; sigs[i].name != NULL; i++) {
			if (strcasecmp(sigs[i].name, signame) == 0)
				break;
		}
		sig = sigs[i].num;
	}
	if (sig < 0 || sig >= NSIG)
		errx(ecode, "signal %s out of range", signame);
	return (sig);
} /* parse_sig */


/*
 * parse_wait --
 *	Parse the string for the time to wait
 */
int
parse_wait(const char *waittime)
{
	int		 wait;
	const char	*p;

	p = waittime;
	while (*p && isdigit(*p))
		p++;
	if (*p != '\0')
		errx(ecode, "invalid wait '%s'", waittime);
	wait = atoi(waittime);
	if (wait < 0)
		errx(ecode, "wait %d out of range", wait);
	return (wait);
} /* parse_wait */


/*
 * process_log --
 *	Perform any processing upon the log.
 */
void
process_log(const char *log, const char *prog)
{
    /* XXX: check retvals here */
	const char	*from;
	char		*logdir, *logbase;
	char		*command, *to;
	size_t		 cmdlen;
	int		 pid;

	cmdlen = 0;
	splitpath(log, &logdir, &logbase);

	for (from = prog; *from; from++) {
		if (*from != '%') {
			cmdlen++;
			continue;
		}
		from++;
		switch (*from) {
		case '\0':
			errx(ecode, "%% format requires a specifier");
		case '%':
			cmdlen++;
			break;
		case 'd':
			cmdlen += strlen(logdir);
			break;
		case 'f':
			cmdlen += strlen(logbase);
			break;
		case 'p':
			cmdlen += strlen(log);
			break;
		default:
			errx(ecode, "%%%c not supported in postfilter_log",
			    *from);
		}
	}
	command = (char *) malloc((cmdlen + 1) * sizeof(char *));
	if (command == NULL)
		errx(ecode, "can't allocate memory");
	to = command;
	for (from = prog; *from; from++) {
		if (to >= command + cmdlen)
			errx(ecode,
			    "postfilter_log buffer overrun (shouldn't happen)");
		if (*from != '%') {
			*to++ = *from;
			continue;
		}
		from++;
		switch (*from) {
		case '%':
			*to++ = *from;
			break;
		case 'd':
			(void) strcat(to, logdir);
			to += strlen(logdir);
			break;
		case 'b':
			(void) strcat(to, logbase);
			to += strlen(logbase);
			break;
		case 'p':
			(void) strcat(to, log);
			to += strlen(log);
			break;
		default:
			errx(ecode, "%%%c unexpected in postfilter_log", *from);
		}
	}
	*to++ = '\0';

	switch (pid = fork()) {
	case -1:
		err(ecode, "can't fork");
	case 0:
		for (pid = 3 ; pid < MAXFD; pid++)
			close(pid);
		execl(PATH_BSHELL, "sh", "-c", command, NULL);
		err(ecode, "can't exec sh to run %s", command);
	default:
		if (waitpid(pid, NULL, 0) == -1)
			errx(ecode, "error running %s", command);
	}
	free(logdir);
	free(logbase);
} /* process_log */


/*
 * rotate_log --
 *	Move the given log aside, create a new one with the same
 *	permissions, and send signal sig to pid.
 *	Returns a pointer to a malloc(3)ed string containing the
 *	temporary name of the new log file
 */
char *
rotate_log(const char *log, pid_t pid, int sig, int wait)
{
	struct stat stbuf;
	char	newlog[MAXPATHLEN];	/* temp file for newly rotated log */
	char	origlog[MAXPATHLEN];	/* temp file to put back as original */
	char   *logdir, *logbase;
	int	newfd, origfd;

	newfd = origfd = -1;
	splitpath(log, &logdir, &logbase);

	if (stat(log, &stbuf) == -1)
		err(ecode, "can't stat '%s'", log);

		/* create temp file for newly rotated log */
#undef	EXTENSION
#define EXTENSION	".logrot.XXXXXX"
	if (strlen(log) + sizeof(EXTENSION) + 1  >= sizeof(origlog)) {
		warnx("length of '%s' is too long", log);
		goto abort_rotate_log;
	}
	sprintf(origlog, "%s/%s%s", logdir, logbase, EXTENSION);
	if ((origfd = mkstemp(origlog)) == -1) {
		warn("mkstemp '%s' failed", origlog);
		goto abort_rotate_log;
	}
	if (fchmod(origfd, stbuf.st_mode) == -1) {
		warn("can't fchmod '%s' to %o", origlog, (int)stbuf.st_mode);
		goto abort_rotate_log;
	}
	if (fchown(origfd, stbuf.st_uid, stbuf.st_gid) == -1) {
		warn("can't fchown '%s' to %d,%d", origlog,
		    (int)stbuf.st_uid, (int)stbuf.st_gid);
		goto abort_rotate_log;
	}

		/* create temp file to rename to the original log */
#undef	EXTENSION
#define EXTENSION	".newlog.XXXXXX"
	if (strlen(log) + sizeof(EXTENSION) + 1  >= sizeof(newlog)) {
		warnx("length of '%s' is too long", log);
		goto abort_rotate_log;
	}
	sprintf(newlog, "%s/%s%s", logdir, logbase, EXTENSION);
	if ((newfd = mkstemp(newlog)) == -1) {
		warn("mkstemp '%s' failed", newlog);
		goto abort_rotate_log;
	}
	if (fchmod(newfd, stbuf.st_mode) == -1) {
		warn("can't fchmod '%s' to %o", newlog, (int)stbuf.st_mode);
		goto abort_rotate_log;
	}
	if (fchown(newfd, stbuf.st_uid, stbuf.st_gid) == -1) {
		warn("can't fchown '%s' to %d,%d", newlog,
		    (int)stbuf.st_uid, (int)stbuf.st_gid);
		goto abort_rotate_log;
	}

		/* rotate the original log to the temp rotated log */
	if (rename(log, origlog) == -1) {
		warn("can't rename '%s' to '%s'", log, origlog);
		goto abort_rotate_log;
	}
		
		/*
		 * At this point, the original log file has been moved
		 * aside, but the new (empty) log file hasn't been
		 * moved into place. Move the empty into place ASAP!
		 */

		/* rotate the new log to the log */
	if (rename(newlog, log) == -1) {
		warn("can't rename '%s' to '%s'", newlog, log);
		goto abort_rotate_log;
	}

	ecode = 1;	/* temp file exists; set exit code to indicate this */

	close(newfd);
	close(origfd);

		/* signal the process then wait a bit */
	if (pid != 0) {
		if (kill(pid, sig) == -1)
			errx(ecode, "can't send sig %d to %d", sig, (int)pid);
		sleep(wait);
	}

	free(logdir);
	free(logbase);
	return (xstrdup(origlog));		/* successful exit point */

abort_rotate_log:
	if (newfd != -1) {
		close(newfd);
		unlink(newlog);
	}
	if (origfd != -1) {
		close(origfd);
		unlink(origlog);
	}
	free(logdir);
	free(logbase);
	exit(ecode);
} /* rotate_log */


/*
 * splitpath --
 *	Break a path into dirname and basename components. If there
 *	is no leading directory, "." is returned for the directory.
 *	The resultant strings are allocated with malloc(3) and
 *	should be released by the caller with free(3).
 */
void
splitpath(const char *path, char **dir, char **base)
{
	char	*o;

	o = strrchr(path, '/');
	if (o == NULL) {
		*dir = xstrdup(".");
		*base = xstrdup(path);
	} else if (o == path) {
		*dir = xstrdup("/");
		*base = xstrdup(path + 1);
	} else {
		*dir = xstrdup(path);
		(*dir)[o - path] = '\0';
		*base = xstrdup(o + 1);
	}
} /* splitpath */


/*
 * xstrdup --
 *	strdup() the given string, and return the result.
 *	If the string is NULL, return NULL.
 *	Prints a message to stderr and exits with a non-zero
 *	return code if the memory couldn't be allocated.
 */
char *
xstrdup(const char *str)
{
	char	*newstr;
	size_t	 len;

	if (str == NULL)
		return NULL;

	len = strlen(str) + 1;
	newstr = malloc(len);
	if (newstr == NULL)
		errx(ecode, "can't allocate memory");
	memcpy(newstr, str, len);
	return (newstr);
} /* xstrdup */
