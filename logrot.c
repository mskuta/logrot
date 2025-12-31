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

/*
 * exit values
 */
enum { E_SUCCESS, E_TEMPFILEEXISTS, E_NOTEMPFILE, E_USAGE } ecode;

/*
 * name of program (for error messages)
 */
char* progname;

/*
 * options setting a flag
 */
static int copytruncateflag;
static int createflag;

/*
 * xmalloc --
 *	malloc the requested amount of memory.
 *	Prints a message to stderr and exits with a non-zero
 *	return code if the memory couldn't be allocated.
 */
static void* xmalloc(size_t size) {
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
static char* xstrdup(const char* str) {
	char* newstr;
	size_t len;

	if (str == NULL)
		return NULL;

	len = strlen(str) + 1;
	newstr = xmalloc(len);
	memcpy(newstr, str, len);
	return (newstr);
} /* xstrdup */

/*
 * splitpath --
 *	Break a path into dirname and basename components. If there
 *	is no leading directory, "." is returned for the directory.
 *	The resultant strings are allocated with malloc(3) and
 *	should be released by the caller with free(3).
 */
static void splitpath(const char* path, char** dir, char** base) {
	const char* const o = strrchr(path, '/');
	if (o == NULL) {
		*dir = xstrdup(".");
		*base = xstrdup(path);
	}
	else if (o == path) {
		*dir = xstrdup("/");
		*base = xstrdup(path + 1);
	}
	else {
		*dir = xstrdup(path);
		(*dir)[o - path] = '\0';
		*base = xstrdup(o + 1);
	}
} /* splitpath */

/*
 * run_command --
 *	run the given command (via /bin/sh -c command)
 */
static void run_command(const char* command) {
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
static char* filter_log(const char* origlog, const char* rotlog, const char* filter_prog, const char* compress_prog, const char* compress_ext) {
	struct stat stbuf;
	char outfile[MAXPATHLEN];
	int infd, outfd, pipefd[2], ispipe, junkfd;
	int filter_pid, compress_pid, rstat;

	if (strlcpy(outfile, rotlog, sizeof outfile) >= sizeof outfile || (compress_prog != NULL && strlcat(outfile, compress_ext, sizeof outfile) >= sizeof outfile))
		errx(ecode, "rotated filename would be too long");

	if ((infd = open(origlog, O_RDONLY)) == -1)
		err(ecode, "can't open '%s'", origlog);

	if ((outfd = open(outfile, O_WRONLY | O_CREAT | O_EXCL, 0700)) == -1)
		err(ecode, "can't open '%s' for writing", outfile);

	filter_pid = -1;
	compress_pid = -1;
	ispipe = 0;

	if (filter_prog != NULL && compress_prog != NULL) {
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
		char xferbuf[BUFSIZ];
		ssize_t in;
		while ((in = read(infd, xferbuf, sizeof(xferbuf))) > 0) {
			char* tmp = xferbuf;
			ssize_t out;
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
	ecode = E_NOTEMPFILE;

	return (xstrdup(outfile));
} /* filter_log */

/*
 * process_log --
 *	Perform any processing upon the log.
 */
static void process_log(const char* log, const char* prog) {
	const char* from;
	char *logdir, *logbase;
	char *command, *to;
	size_t cmdlen;

	cmdlen = 0;
	splitpath(log, &logdir, &logbase);

	/* first pass: compute required length */
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
	command = xmalloc(cmdlen + 1);
	to = command;

	/* second pass: build command */
	size_t len;
	for (from = prog; *from; from++) {
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
				len = strlen(logdir);
				memcpy(to, logdir, len);
				to += len;
				break;
			case 'f':
				len = strlen(logbase);
				memcpy(to, logbase, len);
				to += len;
				break;
			case 'p':
				len = strlen(log);
				memcpy(to, log, len);
				to += len;
				break;
			default:
				errx(ecode, "%%%c unexpected in postfilter_log", *from);
		}
	}
	*to = '\0';
	free(logdir);
	free(logbase);
	run_command(command);
	free(command);
} /* process_log */

/*
 * rotate_log --
 *	Move the given log aside and (optionally) create a new one with the
 *	same permissions and owner, or copy and truncate it.
 *	Returns a pointer to a malloc(3)ed string containing the temporary
 *	name of the original file.
 */
static char* rotate_log(const char* logpath) {
	struct stat statb, statb2;
	if (stat(logpath, &statb) == -1 || lstat(logpath, &statb2) == -1) {
		warn("%s", logpath);
		return NULL;
	}
	if (!S_ISREG(statb.st_mode) || S_ISLNK(statb2.st_mode)) {
		warnx("not a regular file or a link: %s", logpath);
		return NULL;
	}

	char buf[MAXPATHLEN];
	char* logbase;
	char* logdir;
	int size;
	splitpath(logpath, &logdir, &logbase);
	size = snprintf(buf, sizeof buf, "%s/%s%s", logdir, logbase, ".logrot.XXXXXX");
	free(logbase);
	free(logdir);
	if (size == -1) {
		warnx("building temporary path failed for: %s", logpath);
		return NULL;
	}
	if ((size_t)size >= sizeof buf) {
		warnx("temporary path would be too long for: %s", logpath);
		return NULL;
	}

	const int fd = mkstemp(buf);
	if (fd == -1) {
		warn("%s", buf);
		return NULL;
	}

	bool success = false;
	if (fchmod(fd, statb.st_mode) == -1 || fchown(fd, statb.st_uid, statb.st_gid) == -1) {
		warn("fchmod || fchown");
	}
	else {
		if (copytruncateflag) {
			const int fd2 = open(logpath, O_RDWR);
			if (fd2 == -1) {
				warn("%s", logpath);
			}
			else {
				off_t len = statb.st_size;
				ssize_t ret;
				do {
					ret = copy_file_range(fd2, NULL, fd, NULL, len, 0);
					len -= ret;
				} while (len > 0 && ret > 0);
				if (ret == -1) {
					warn("copy_file_range");
				}
				else {
					if (ftruncate(fd2, 0) == -1)
						warn("ftruncate");
					else
						success = true;
				}
				(void)close(fd2);
			}
		}
		else {
			if (rename(logpath, buf) == -1) {
				warn("rename");
			}
			else {
				success = true;
				if (createflag) {
					const int fd2 = open(logpath, O_WRONLY | O_CREAT, statb.st_mode);
					if (fd2 == -1) {
						warn("%s", logpath);
					}
					else {
						if (fchown(fd2, statb.st_uid, statb.st_gid) == -1) {
							warn("fchown");
							(void)unlink(logpath);
						}
						(void)close(fd2);
					}
				}
			}
		}
	}
	(void)close(fd);
	if (!success) {
		(void)unlink(buf);
		return NULL;
	}
	ecode = E_TEMPFILEEXISTS;
	return xstrdup(buf);
} /* rotate_log */

/*
 * parse_rotate_fmt --
 *	Parse the rotate format and build the target filename.
 *	Returns a pointer to a malloc(3)ed string containing the target
 *	filename.
 */
static char* parse_rotate_fmt(const char* logpath, const char* dir, const char* fmt, time_t now) {
	const struct tm* const tmp = localtime(&now);
	if (tmp == NULL) {
		warn("localtime");
		return NULL;
	}

	char buf[MAXPATHLEN];
	char* logbase;
	char* logdir;
	int size;
	splitpath(logpath, &logdir, &logbase);
	if (dir == NULL)  // original dir
		size = snprintf(buf, sizeof buf, "%s/%s", logdir, logbase);
	else if (dir[0] == '/')  // absolute dir
		size = snprintf(buf, sizeof buf, "%s/%s", dir, logbase);
	else  // relative dir
		size = snprintf(buf, sizeof buf, "%s/%s/%s", logdir, dir, logbase);
	free(logbase);
	free(logdir);
	if (size == -1) {
		warnx("building destination path failed for: %s", logpath);
		return NULL;
	}
	else if ((size_t)size >= sizeof buf) {
		warnx("destination path would be too long for: %s", logpath);
		return NULL;
	}

	const char* const bufend = buf + sizeof buf - 1;
	char format[3];
	char* to = buf + strlen(buf);
	for (const char* from = fmt; *from; from++) {
		if (to > bufend) {
			warnx("date extension is too long for: %s", logpath);
			return NULL;
		}
		if (*from != '%') {
			*to++ = *from;
			continue;
		}
		from++;
		switch (*from) {
			case '\0':
				warnx("%% format requires a specifier");
				return NULL;
			case '%':
				*to++ = *from;
				break;
			case 'Y':
			case 'm':
			case 'd':
			case 'H':
			case 'M':
			case 'S':
			case 'V':
			case 's':
				sprintf(format, "%%%c", *from);
				to += strftime(to, bufend - to, format, tmp);
				break;
			default:
				warnx("%%%c not supported as format specifier", *from);
				return NULL;
		}
	}
	return xstrdup(buf);
} /* parse_rotate_fmt */

/*
 * parse_pid --
 *	Determine pid of process from pidfile.
 *	The first word of the pidfile will be used as the pid
 */
static pid_t parse_pid(const char* pidfile) {
	FILE* pf;
	char buf[BUFSIZ];
	pid_t pid;

	if ((pf = fopen(pidfile, "r")) == NULL)
		err(ecode, "can't open '%s'", pidfile);
	pid = 0;
	if (fgets(buf, sizeof(buf), pf) != NULL) {
		char* p = buf;
		while (*p != '\0' && isdigit((int)*p))
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
 * parse_wait --
 *	Parse the string for the time to wait
 */
static int parse_wait(const char* waittime) {
	int wait;
	const char* p;

	p = waittime;
	while (*p != '\0' && isdigit((int)*p))
		p++;
	if (*p != '\0')
		errx(ecode, "invalid wait '%s'", waittime);
	wait = atoi(waittime);
	if (wait < 0)
		errx(ecode, "wait %d out of range", wait);
	return (wait);
} /* parse_wait */

/*
 * parse_sig --
 *	Parse the given string for a signal name or number.
 */
static int parse_sig(const char* signame) {
	// clang-format off
	struct sig_list {
		int num;
		char* name;
	} sigs[] = {
		{ SIGHUP,  "HUP"  },
		{ SIGINT,  "INT"  },
		{ SIGQUIT, "QUIT" },
		{ SIGTERM, "TERM" },
		{ SIGUSR1, "USR1" },
		{ SIGUSR2, "USR2" },
		{ -1,      NULL   },
	};
	// clang-format on

	int sig;
	if (isdigit((int)*signame)) {
		const char* p;

		p = signame;
		while (*p != '\0' && isdigit((int)*p))
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
 * usage --
 *	Display a usage message and exit
 */
static void usage(void) {
	fprintf(stderr,
	        "Usage: %s\t[-c] [-C compressor] [-d destdir] [-f filter] [-B preprocessor]\n"
	        "\t\t[-F postprocessor] [-N notifycmd] [-p pidfile] [-r rotate_fmt]\n"
	        "\t\t[-s sig] [-w wait] [-X compress_extension] file [file ...]\n",
	        progname);
	exit(E_USAGE);
} /* usage */

/*
 * main --
 *	Main entry point
 */
int main(int argc, char* argv[]) {
	if ((progname = strrchr(argv[0], '/')) == NULL)
		progname = argv[0];
	else
		progname++;

	// set initial exit value
	ecode = E_NOTEMPFILE;

	// set default values for options
	int compress = 0;                           // non-zero if compression required
	const char* compress_ext = COMPRESS_EXT;    // extension of compressed files
	const char* compress_prog = COMPRESS_PROG;  // compression program to use
	const char* destdir = NULL;                 // destination of rotated logfile
	const char* filter_prog = NULL;             // in-line filter program
	const char* notify_command = NULL;          // command to run to notify of rotate
	const char* pidfile = DEFAULT_PIDFILE;      // pidfile containing pid to signal
	const char* postprocess_prog = NULL;        // pre compression filter program
	const char* preprocess_prog = NULL;         // post compression filter program
	const char* rotate_fmt = DEFAULT_FORMAT;    // format of rotated logfile name
	int sig = DEFAULT_SIGNAL;                   // signal to send to pid
	int wait = DEFAULT_WAIT;                    // waittime after signal until rotate

	// process options from command line
	int ch;
	// clang-format off
	static struct option longopts[] = {
		{ "compress",     no_argument,       NULL,              'c' },
		{ "compresscmd",  required_argument, NULL,              'C' },
		{ "compressext",  required_argument, NULL,              'X' },
		{ "copytruncate", no_argument,       &copytruncateflag, 1   },
		{ "create",       no_argument,       &createflag,       1   },
		{ "dateformat",   required_argument, NULL,              'r' },
		{ "olddir",       required_argument, NULL,              'd' },
		{ "postrotate",   required_argument, NULL,              'F' },
		{ "prerotate",    required_argument, NULL,              'B' },
		{ NULL,           0,                 NULL,              0   }
	};
	// clang-format on
	int longindex = 0;
	while ((ch = getopt_long(argc, argv, "B:cC:d:f:F:N:p:r:s:w:X:", longopts, &longindex)) != -1) {
		switch (ch) {
			case 0:
				break;
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
		}
	}
	argc -= optind;
	argv += optind;
	if (argc < 1)
		usage();

	// get PID to signal
	pid_t pid = 0;
	if (pidfile != NULL && pidfile[0] != '\0' && sig != 0)
		pid = parse_pid(pidfile);

	StringList* const origlogs = sl_init();  // paths for temporary copies of the original logs
	StringList* const rotlogs = sl_init();   // paths of the rotated logs
	if (origlogs == NULL || rotlogs == NULL)
		err(ecode, "stringlist");

	// move the original logs aside
	time_t now;
	(void)time(&now);
	for (int idx = 0; idx < argc; idx++) {
		char* const rotlog = parse_rotate_fmt(argv[idx], destdir, rotate_fmt, now);
		if (rotlog != NULL) {
			char* const origlog = rotate_log(argv[idx]);
			if (origlog != NULL) {
				// abort if there cannot be a 1:1 relationship between these paths
				if (!sl_add(origlogs, origlog) || !sl_add(rotlogs, rotlog))
					err(ecode, "stringlist");
			}
			else {
				// skip this argument and continue
				free(rotlog);
			}
		}
	}

	// signal the process then wait a bit
	if (pid != 0) {
		if (kill(pid, sig) == -1)
			errx(ecode, "kill() failed sending signal %d to process %d", sig, (int)pid);
		sleep(wait);
	}
	else if (notify_command != NULL) {
		run_command(notify_command);
		sleep(wait);
	}

	// run the preprocessor
	if (preprocess_prog != NULL && preprocess_prog[0] != '\0')
		for (size_t idx = 0; idx < origlogs->sl_cur; idx++)
			process_log(origlogs->sl_str[idx], preprocess_prog);

	// run the filter and compression
	StringList* const finallogs = sl_init();
	if (finallogs == NULL)
		err(ecode, "stringlist");
	for (size_t idx = 0; idx < origlogs->sl_cur; idx++)
		if (!sl_add(finallogs, filter_log(origlogs->sl_str[idx], rotlogs->sl_str[idx], filter_prog, compress ? compress_prog : NULL, compress_ext)))
			warn("stringlist");
	sl_free(origlogs, 1);
	sl_free(rotlogs, 1);

	// run the postprocessor
	if (postprocess_prog != NULL && postprocess_prog[0] != '\0')
		for (size_t idx = 0; idx < finallogs->sl_cur; idx++)
			process_log(finallogs->sl_str[idx], postprocess_prog);
	sl_free(finallogs, 1);

	// well done
	exit(E_SUCCESS);
} /* main */
