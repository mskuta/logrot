/*
 * Copyright 1997-2001, 2005 Luke Mewburn <luke@mewburn.net>.
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

#include "logrot.h"

char* filter_log(const char*, const char*, const char*, const char*, const char*);
int main(int, char*[]);
pid_t parse_pid(const char*);
StringList* parse_rotate_fmt(const char*, const char*, int, char**, time_t);
int parse_sig(const char*);
int parse_wait(const char*);
void process_log(const char*, const char*);
StringList* rotate_logs(int, char**, pid_t, int, const char*, int);
void run_command(const char*);
void splitpath(const char*, char**, char**);
void* xmalloc(size_t size);
char* xstrdup(const char*);
void usage(void);

/*
 * failure exit value:
 *	1 = temp file exists
 *	2 = no temp file
 */
int ecode;

/*
 * name of program (for error messages)
 */
char* progname;

/*
 * usage --
 *	Display a usage message and exit
 */
void usage(void) {
	fprintf(stderr,
	        "Usage: %s\t[-c] [-C compressor] [-d destdir] [-f filter] [-B preprocessor]\n"
	        "\t\t[-F postprocessor] [-N notifycmd] [-p pidfile] [-r rotate_fmt]\n"
	        "\t\t[-s sig] [-w wait] [-X compress_extension] file [file ...]\n",
	        progname);
	exit(1);
} /* usage */

/*
 * main --
 *	Main entry point
 */
int main(int argc, char* argv[]) {
	StringList *rotlogs, *origlogs, *finallogs;
	int compress;           /* non-zero if compression required */
	char* compress_prog;    /* compression program to use */
	char* compress_ext;     /* extension of compressed files */
	char* destdir;          /* destination of rotated logfile */
	char* filter_prog;      /* in-line filter program */
	char* pidfile;          /* pidfile containing pid to signal */
	char* preprocess_prog;  /* pre compression filter program */
	char* postprocess_prog; /* post compression filter program */
	char* rotate_fmt;       /* format of rotated logfile name */
	char* notify_command;   /* command to run to notify of rotate */
	pid_t pid;              /* pid to signal */
	int sig;                /* signal to send to pid */
	int wait;               /* waittime after signal until rotate */

	time_t now;
	int ch;

	(void)umask(077); /* be safe when creating temp files */

	ecode = 2; /* exit val for no temp file */

	splitpath(argv[0], NULL, &progname);

	compress = 0;
	compress_prog = COMPRESS_PROG;
	compress_ext = COMPRESS_EXT;
	destdir = NULL;
	filter_prog = NULL;
	pidfile = DEFAULT_PIDFILE;
	postprocess_prog = NULL;
	preprocess_prog = NULL;
	rotate_fmt = DEFAULT_FORMAT;
	notify_command = NULL;
	pid = 0;
	sig = DEFAULT_SIGNAL;
	wait = DEFAULT_WAIT;

	while ((ch = getopt(argc, argv, "B:cC:d:f:F:N:p:r:s:w:X:")) != -1) {
		switch (ch) {
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
			case 'N':
				notify_command = optarg;
				sig = 0;
				break;
			case 'p':
				pidfile = optarg;
				break;
			case 'r':
				rotate_fmt = optarg;
				break;
			case 's':
				sig = parse_sig(optarg);
				notify_command = NULL;
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
	argc -= optind;
	argv += optind;
	if (argc < 1)
		usage();

	if (pidfile && pidfile[0] && sig)
		pid = parse_pid(pidfile);

	(void)time(&now);
	rotlogs = parse_rotate_fmt(rotate_fmt, destdir, argc, argv, now);
	origlogs = rotate_logs(argc, argv, pid, sig, notify_command, wait);
	if (preprocess_prog && preprocess_prog[0]) {
		for (size_t idx = 0; idx < origlogs->sl_cur; idx++)
			process_log(origlogs->sl_str[idx], preprocess_prog);
	}
	finallogs = sl_init();
	for (size_t idx = 0; idx < origlogs->sl_cur; idx++) {
		sl_add(finallogs, filter_log(origlogs->sl_str[idx], rotlogs->sl_str[idx], filter_prog, compress ? compress_prog : NULL, compress_ext));
	}
	if (postprocess_prog && postprocess_prog[0]) {
		for (size_t idx = 0; idx < finallogs->sl_cur; idx++)
			process_log(finallogs->sl_str[idx], postprocess_prog);
	}

	sl_free(origlogs, 1);
	sl_free(rotlogs, 1);
	sl_free(finallogs, 1);
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
char* filter_log(const char* origlog, const char* rotlog, const char* filter_prog, const char* compress_prog, const char* compress_ext) {
	struct stat stbuf;
	char outfile[MAXPATHLEN];
	int infd, outfd, pipefd[2], ispipe, junkfd;
	int filter_pid, compress_pid, rstat;

	if ((strlen(rotlog) + (compress_prog != NULL ? strlen(compress_ext) : 0) + 1) > sizeof(outfile))
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
				if (dup2(ispipe ? pipefd[1] : outfd, fileno(stdout)) == -1)
					err(ecode, "can't dup2 filter stdout");
				for (junkfd = 3; junkfd < MAXFD; junkfd++)
					close(junkfd);
				execl(PATH_BSHELL, "sh", "-c", filter_prog, NULL);
				err(ecode, "can't exec sh to run '%s'", filter_prog);
			default:
				if (ispipe)
					close(pipefd[1]);
		}
	}

	if (compress_prog) {
		switch (compress_pid = fork()) {
			case -1:
				err(ecode, "can't fork");
			case 0:
				if (dup2(ispipe ? pipefd[0] : infd, fileno(stdin)) == -1)
					err(ecode, "can't dup2 compress stdin");
				if (dup2(outfd, fileno(stdout)) == -1)
					err(ecode, "can't dup2 compress stdout");
				for (junkfd = 3; junkfd < MAXFD; junkfd++)
					close(junkfd);
				execl(PATH_BSHELL, "sh", "-c", compress_prog, NULL);
				err(ecode, "can't exec sh to run '%s'", compress_prog);
			default:
				if (ispipe)
					close(pipefd[0]);
		}
	}

	/*
	 * direct copy required
	 */
	if (filter_pid == -1 && compress_pid == -1) {
		char xferbuf[BUFSIZ], *tmp;
		ssize_t in, out;

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
	}
	else
		while (filter_pid != -1 || compress_pid != -1) {
			/*
			 * XXX:	differentiate between child being stopped
			 *	with SIGSTOP/SIGTSTP, and child exiting ok.
			 */
			if ((filter_pid != -1) && (waitpid(filter_pid, &rstat, WNOHANG) != 0)) {
				if (WIFEXITED(rstat) != 0) {
					if (WEXITSTATUS(rstat) != 0)
						errx(ecode, "'%s' exited with %d", filter_prog, WEXITSTATUS(rstat));
#if defined(WIFSIGNALED)
				}
				else if (WIFSIGNALED(rstat) != 0) {
					errx(ecode, "'%s' exited due to signal %d", filter_prog, WTERMSIG(rstat));
#endif
				}
				else {
					errx(ecode, "'%s' returned status %d - why?", filter_prog, rstat);
				}
				filter_pid = -1;
			}
			if ((compress_pid != -1) && (waitpid(compress_pid, &rstat, WNOHANG) != 0)) {
				if (WIFEXITED(rstat) != 0) {
					if (WEXITSTATUS(rstat) != 0)
						errx(ecode, "'%s' exited with %d", compress_prog, WEXITSTATUS(rstat));
#if defined(WIFSIGNALED)
				}
				else if (WIFSIGNALED(rstat) != 0) {
					errx(ecode, "'%s' exited due to signal %d", compress_prog, WTERMSIG(rstat));
#endif
				}
				else {
					errx(ecode, "'%s' returned status %d - why?", compress_prog, rstat);
				}
				compress_pid = -1;
			}
			sleep(1);
		}

	if (fstat(infd, &stbuf) == -1)
		err(ecode, "can't stat '%s'", outfile);
	if (fchmod(outfd, stbuf.st_mode) == -1)
		err(ecode, "can't fchmod '%s' to %o", outfile, (int)stbuf.st_mode);
	if (fchown(outfd, stbuf.st_uid, stbuf.st_gid) == -1)
		err(ecode, "can't fchown '%s' to %d,%d", outfile, (int)stbuf.st_uid, (int)stbuf.st_gid);
	close(infd);
	close(outfd);
	if (unlink(origlog) == -1)
		err(ecode, "can't unlink '%s'", origlog);
	ecode = 2; /* temp file gone; set exit code to indicate this */

	return (xstrdup(outfile));
} /* filter_log */

/*
 * parse_pid --
 *	Determine pid of process from pidfile.
 *	The first word of the pidfile will be used as the pid
 */
pid_t parse_pid(const char* pidfile) {
	FILE* pf;
	char buf[BUFSIZ], *p;
	pid_t pid;

	if ((pf = fopen(pidfile, "r")) == NULL)
		err(ecode, "can't open '%s'", pidfile);
	pid = 0;
	if (fgets(buf, sizeof(buf), pf) != NULL) {
		p = buf;
		while (*p && isdigit((int)*p))
			p++;
		if (*p == '\0' || isspace((int)*p)) {
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
 *	Parse the rotate format and build the target filenames.
 *	Returns a StringList containing the target filenames.
 */
StringList* parse_rotate_fmt(const char* fmt, const char* dir, int logc, char** logs, time_t now) {
	struct stat stbuf;
	char buf[MAXPATHLEN];
	char* bufend;
	char *logdir, *logbase;
	const char* from;
	char* to;
	char *junk1, junk2[4];
	struct tm* tmnow;
	StringList* sl;

	tmnow = localtime(&now);
	sl = sl_init();
	for (int idx = 0; idx < logc; idx++) {
		if ((strlen(logs[idx]) + (dir != NULL ? strlen(dir) : 0) + 3) > sizeof(buf))
			errx(ecode, "format '%s' is too long", fmt);
		splitpath(logs[idx], &logdir, &logbase);

		bufend = buf + sizeof(buf) - 1;

		memset(buf, 0, sizeof(buf) - 1);
		buf[0] = '\0';
		if (dir == NULL) /* default dir `file.d' */
			sprintf(buf, "%s/%s.d", logdir, logbase);
		else if (dir[0] == '/') /* fully qualified dir */
			sprintf(buf, "%s", dir);
		else /* specific dir */
			sprintf(buf, "%s/%s", logdir, dir);
		if (stat(buf, &stbuf) == -1) {
			if (errno == ENOENT) {
				warnx("%s doesn't exist - using %s instead", buf, logdir);
				strcpy(buf, logdir);
			}
			else
				err(ecode, "can't stat %s", buf);
		}
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
						errx(ecode, "%%%c in format '%s' is too long", *from, fmt);
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
		}
		else
			errx(ecode, "%s already exists", buf);
		sl_add(sl, xstrdup(buf));

		free(logdir);
		free(logbase);
	}
	return (sl);
} /* parse_rotate_fmt */

/*
 * parse_sig --
 *	Parse the given string for a signal name or number.
 */
int parse_sig(const char* signame) {
	struct sig_list {
		int num;
		char* name;
	} sigs[] = {
		{
		  SIGHUP,
		  "HUP",
		},
		{
		  SIGINT,
		  "INT",
		},
		{
		  SIGQUIT,
		  "QUIT",
		},
		{
		  SIGTERM,
		  "TERM",
		},
		{
		  SIGUSR1,
		  "USR1",
		},
		{
		  SIGUSR2,
		  "USR2",
		},
		{
		  -1,
		  NULL,
		},
	};

	int sig;

	sig = 0;
	if (isdigit((int)*signame)) {
		const char* p;

		p = signame;
		while (*p && isdigit((int)*p))
			p++;
		if (*p != '\0')
			errx(ecode, "invalid signal '%s'", signame);
		sig = atoi(signame);
	}
	else {
		int i;

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
int parse_wait(const char* waittime) {
	int wait;
	const char* p;

	p = waittime;
	while (*p && isdigit((int)*p))
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
void process_log(const char* log, const char* prog) {
	/* XXX: check retvals here */
	const char* from;
	char *logdir, *logbase;
	char *command, *to;
	size_t cmdlen;

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
				errx(ecode, "%%%c not supported in postfilter_log", *from);
		}
	}
	command = (char*)xmalloc((cmdlen + 1) * sizeof(char*));
	to = command;
	for (from = prog; *from; from++) {
		if (to >= command + cmdlen)
			errx(ecode, "postfilter_log buffer overrun (shouldn't happen)");
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
				(void)strcat(to, logdir);
				to += strlen(logdir);
				break;
			case 'f':
				(void)strcat(to, logbase);
				to += strlen(logbase);
				break;
			case 'p':
				(void)strcat(to, log);
				to += strlen(log);
				break;
			default:
				errx(ecode, "%%%c unexpected in postfilter_log", *from);
		}
	}
	*to++ = '\0';
	free(logdir);
	free(logbase);

	run_command(command);
} /* process_log */

/*
 * rotate_logs --
 *	Move the given log aside, create a new one with the same
 *	permissions, and send signal sig to pid.
 *	Returns a pointer to a malloc(3)ed string containing the
 *	temporary name of the new log file
 */
StringList* rotate_logs(int logc, char** logs, pid_t pid, int sig, const char* notify_command, int wait) {
	struct stat stbuf;
	char *logdir, *logbase, *buf;
	int fd;
	StringList* newlogs;  /* temp files for new rotated logs */
	StringList* origlogs; /* temp files to put back as original */
	int* rotated;

	newlogs = sl_init();
	origlogs = sl_init();
	fd = -1;
	rotated = NULL;

	for (int idx = 0; idx < logc; idx++) {
		splitpath(logs[idx], &logdir, &logbase);

		if (stat(logs[idx], &stbuf) == -1) {
			warn("can't stat '%s'", logs[idx]);
			goto abort_rotate_logs;
		}
		if (!S_ISREG(stbuf.st_mode)) {
			warnx("'%s' isn't a regular file", logs[idx]);
			goto abort_rotate_logs;
		}

		/* create temp file for newly rotated log */
#undef EXTENSION
#define EXTENSION ".logrot.XXXXXX"
		if ((strlen(logs[idx]) + sizeof(EXTENSION) + 1) >= MAXPATHLEN) {
			warnx("length of '%s' is too long", logs[idx]);
			goto abort_rotate_logs;
		}
		buf = xmalloc(MAXPATHLEN);
		sl_add(origlogs, buf);
		sprintf(buf, "%s/%s%s", logdir, logbase, EXTENSION);
		if ((fd = mkstemp(buf)) == -1) {
			warn("mkstemp '%s' failed", buf);
			goto abort_rotate_logs;
		}
		if (fchmod(fd, stbuf.st_mode) == -1) {
			warn("can't fchmod '%s' to %o", buf, (int)stbuf.st_mode);
			goto abort_rotate_logs;
		}
		if (fchown(fd, stbuf.st_uid, stbuf.st_gid) == -1) {
			warn("can't fchown '%s' to %d,%d", buf, (int)stbuf.st_uid, (int)stbuf.st_gid);
			goto abort_rotate_logs;
		}
		close(fd);
		fd = -1;

		/* create temp file to rename to the original log */
#undef EXTENSION
#define EXTENSION ".newlog.XXXXXX"
		if ((strlen(logs[idx]) + sizeof(EXTENSION) + 1) >= MAXPATHLEN) {
			warnx("length of '%s' is too long", logs[idx]);
			goto abort_rotate_logs;
		}
		buf = xmalloc(MAXPATHLEN);
		sl_add(newlogs, buf);
		sprintf(buf, "%s/%s%s", logdir, logbase, EXTENSION);
		if ((fd = mkstemp(buf)) == -1) {
			warn("mkstemp '%s' failed", buf);
			goto abort_rotate_logs;
		}
		if (fchmod(fd, stbuf.st_mode) == -1) {
			warn("can't fchmod '%s' to %o", buf, (int)stbuf.st_mode);
			goto abort_rotate_logs;
		}
		if (fchown(fd, stbuf.st_uid, stbuf.st_gid) == -1) {
			warn("can't fchown '%s' to %d,%d", buf, (int)stbuf.st_uid, (int)stbuf.st_gid);
			goto abort_rotate_logs;
		}
		close(fd);
		fd = -1;
		free(logdir);
		free(logbase);
	}

	/*
	 * build list of flags which indicate how far
	 * the rotation got. values are:
	 *  0	no rotation (remove all temp files)
	 *  1	log moved aside (no new log, and temp log
	 *	still exists)
	 *  2	everything ok
	 */
	rotated = xmalloc(sizeof(int) * logc);
	for (int idx = 0; idx < logc; idx++)
		rotated[idx] = 0;

	/* go through and rotate all the logs */
	for (int idx = 0; idx < logc; idx++) {

		/* rotate the original log to the temp rotated log */
		if (rename(logs[idx], origlogs->sl_str[idx]) == -1) {
			warn("can't rename '%s' to '%s'", logs[idx], origlogs->sl_str[idx]);
			goto abort_rotate_logs;
		}
		rotated[idx] = 1;

		/*
		 * At this point, the original log file has been moved
		 * aside, but the new (empty) log file hasn't been
		 * moved into place. Move the empty into place ASAP!
		 */

		/* rotate the new log to the real log */
		if (rename(newlogs->sl_str[idx], logs[idx]) == -1) {
			warn("can't rename '%s' to '%s'", newlogs->sl_str[idx], logs[idx]);
			goto abort_rotate_logs;
		}
		rotated[idx] = 2;
	}

	ecode = 1; /* temp file exists; set exit code to indicate this */

	/* signal the process then wait a bit */
	if (pid != 0) {
		if (kill(pid, sig) == -1)
			errx(ecode, "can't send sig %d to %d", sig, (int)pid);
		sleep(wait);
	}
	else if (notify_command != NULL) {
		run_command(notify_command);
		sleep(wait);
	}

	return (origlogs); /* successful exit point */

abort_rotate_logs:
	if (fd != -1)
		close(fd);
	for (size_t idx = 0; idx < newlogs->sl_cur; idx++)
		if (rotated == NULL || rotated[idx] < 1)
			unlink(newlogs->sl_str[idx]);
	for (size_t idx = 0; idx < origlogs->sl_cur; idx++)
		if (rotated == NULL || rotated[idx] < 2)
			unlink(origlogs->sl_str[idx]);
	sl_free(origlogs, 1);
	sl_free(newlogs, 1);
	free(logdir);
	free(logbase);
	free(rotated);
	exit(ecode);
} /* rotate_logs */

/*
 * run_command --
 *	run the given command (via /bin/sh -c command)
 */
void run_command(const char* command) {
	pid_t pid;
	int fd;

	switch (pid = fork()) {
		case -1:
			err(ecode, "can't fork");
		case 0:
			for (fd = 3; fd < MAXFD; fd++)
				close(fd);
			execl(PATH_BSHELL, "sh", "-c", command, NULL);
			err(ecode, "can't exec sh to run %s", command);
		default:
			if (waitpid(pid, NULL, 0) == -1)
				errx(ecode, "error running %s", command);
	}
} /* run_command */

/*
 * splitpath --
 *	Break a path into dirname and basename components. If there
 *	is no leading directory, "." is returned for the directory.
 *	The resultant strings are allocated with malloc(3) and
 *	should be released by the caller with free(3).
 */
void splitpath(const char* path, char** dir, char** base) {
	const char* const o = strrchr(path, '/');
	if (o == NULL) {
		if (dir != NULL)
			*dir = xstrdup(".");
		*base = xstrdup(path);
	}
	else if (o == path) {
		if (dir != NULL)
			*dir = xstrdup("/");
		*base = xstrdup(path + 1);
	}
	else {
		if (dir != NULL) {
			*dir = xstrdup(path);
			(*dir)[o - path] = '\0';
		}
		*base = xstrdup(o + 1);
	}
} /* splitpath */

/*
 * xmalloc --
 *	malloc the requested amount of memory.
 *	Prints a message to stderr and exits with a non-zero
 *	return code if the memory couldn't be allocated.
 */

void* xmalloc(size_t size) {
	void* p;

	p = malloc(size);
	if (p == NULL)
		err(1, "memory allocation error");
	return (p);
} /* xmalloc */

/*
 * xstrdup --
 *	strdup() the given string, and return the result.
 *	If the string is NULL, return NULL.
 *	Prints a message to stderr and exits with a non-zero
 *	return code if the memory couldn't be allocated.
 */
char* xstrdup(const char* str) {
	char* newstr;
	size_t len;

	if (str == NULL)
		return NULL;

	len = strlen(str) + 1;
	newstr = xmalloc(len);
	memcpy(newstr, str, len);
	return (newstr);
} /* xstrdup */
