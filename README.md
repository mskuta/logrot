# Description

logrot is log rotation program with many options that should cater
for most people's needs.

It attempts to rotate files in a `safe' manner, in that the window
of time in which the actual log file doesn't exist is minimised
(which is useful when rotating files that have more than one writer,
for example).

The manual page provides details on the various incantation options.


# Installation

```
meson setup --buildtype=release --prefix="$HOME/.local" build
meson install -Cbuild
```


