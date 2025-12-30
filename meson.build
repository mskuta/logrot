# ==================================================================== #
# ===   initialize Meson   =========================================== #
# ==================================================================== #

project('logrot', 'c',
  version: '1.7-mskuta.13',
  meson_version: '>=1.3.0',
  default_options: ['c_std=c99', 'warning_level=3'],
)

compiler = meson.get_compiler('c')
args_req = ['-D_GNU_SOURCE']         # compiler arguments (required)
args_add = []                        # compiler arguments (additional)
srcs = ['logrot.c', 'stringlist.c']  # source files
gzip = ''
pidfile = ''
fs = import('fs')


# ==================================================================== #
# ===   check headers   ============================================== #
# ==================================================================== #

if compiler.has_header('fcntl.h')
  args_add += '-DHAVE_FCNTL_H'
endif
if compiler.has_header('stdarg.h')
  args_add += '-DHAVE_STDARG_H'
endif
if compiler.has_header('stdlib.h')
  args_add += '-DHAVE_STDLIB_H'
endif
if compiler.has_header('string.h')
  args_add += '-DHAVE_STRING_H'
endif
if compiler.has_header('strings.h')
  args_add += '-DHAVE_STRINGS_H'
endif
if compiler.has_header('sys/time.h')
  args_add += '-DHAVE_SYS_TIME_H'
endif
if compiler.has_header('sys/wait.h')
  args_add += '-DHAVE_SYS_WAIT_H'
endif
if compiler.has_header('time.h') and compiler.has_header('sys/time.h')
  args_add += '-DTIME_WITH_SYS_TIME'
endif


# ==================================================================== #
# ===   check functions   ============================================ #
# ==================================================================== #

assert(compiler.has_function('err', args: args_req, prefix: '#include <err.h>'))
assert(compiler.has_function('copy_file_range', args: args_req, prefix: '#include <unistd.h>'))
assert(compiler.has_function('mkstemp', args: args_req, prefix: '#include <stdlib.h>'))
assert(compiler.has_function('strerror', args: args_req, prefix: '#include <string.h>'))
assert(compiler.has_function('strftime', args: args_req, prefix: '#include <time.h>'))
assert(compiler.has_function('waitpid', args: args_req, prefix: ['#include <sys/types.h>', '#include <sys/wait.h>']))
if compiler.has_function('sysconf', args: args_req, prefix: '#include <unistd.h>')
  args_add += '-DHAVE_SYSCONF'
else
  assert(compiler.has_define('OPEN_MAX', args: args_req))
endif


# ==================================================================== #
# ===   find files   ================================================= #
# ==================================================================== #

gzip = find_program('gzip').full_path()
args_add += '-DGZIP="' + gzip + '"'

foreach p : ['/var/run/syslog.pid', '/var/run/syslogd.pid', '/etc/syslog.pid']
  if fs.is_file(p)
    pidfile = p
    break
  endif
endforeach
args_add += '-DPIDFILE="' + pidfile + '"'


# ==================================================================== #
# ===   create executable   ========================================== #
# ==================================================================== #

# expose a series of functions in glibc
add_project_arguments(args_req + args_add, language: 'c')

executable(meson.project_name(), srcs,
  install: true,
  install_dir: get_option('bindir'),
)


# ==================================================================== #
# ===   generate manpage   =========================================== #
# ==================================================================== #

custom_target('manpage',
  input: ['logrot.1.in'],
  output: ['logrot.1'],
  command: ['sed', '-e', f's%!GZIP!%@gzip@%', '-e', f's%!PIDFILE!%@pidfile@%', '@INPUT@'],
  capture: true,
  install: true,
  install_dir: get_option('mandir') / 'man1',
)


# vim: ts=2 sts=0 sw=2 et
