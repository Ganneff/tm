# tm - tmux manager / helper

This is the second version of my tmux helper _tm_, used to ease my
day-to-day work with [tmux](https://github.com/tmux/tmux/wiki).
It is a rewrite in Rust, as I want to learn more Rust. Accidently that
made it much faster too, which is nice.

The rewrite is intended to be, as much as possible, a drop-in
replacement for the old shell version, so any usual _tm s_ or _tm ms_
usage should work right away, as well as the usual config files (see
status for how much is implemented). Still, there might be breakage,
some known ones are mentioned at the end of this document. Feel free
to open an issue, if you notice more.

## Silly badges
[![codecov](https://codecov.io/gh/Ganneff/tm/branch/main/graph/badge.svg?token=KeiO6hIIJQ)](https://codecov.io/gh/Ganneff/tm)
![BSD licensed](https://img.shields.io/badge/license-BSD-blue.svg)

## Usage
tm still tries to support both commandline styles that the shell
script did, that is it can both do the "subcommand" style
(traditional) as well as "getopts" style of old tm.

# More documentation
Need to adapt docs from the old [README.org](old/README.org) to here.

# Status
- [X] Commandline parsing
- [X] Attach to existing sessions
  - [ ] Attach to existing, but "grouped" (seperate window config)
- [X] ls - list sessions
- [X] s  - create new session, open SSH directly to one ore more hosts,
      many windows
- [X] ms - create new session, open SSH directly to one ore more
      hosts, one window with many panes, synchronized input.
- [X] k  - kill session
- [X] -n - Open sessions to same hosts as existing session instead of
      just attaching to that existing session
- [X] Support same environment variables as shell tm
- [X] Simple config files (no ending)
  - [X] Allows LIST command, recursively
  - [X] Support ++TMREPLACETM++
- [ ] Extended config files (.cfg ending)

# How to build
You need [Rust](https://www.rust-lang.org/) on your machine,
installation of that is described at [Rust Install](https://www.rust-lang.org/tools/install).

Afterwards [Cargo](https://doc.rust-lang.org/cargo/), the Rust Package
manager, will help you along, `cargo build --release` should suffice
to install all needed Rust packages and build a binary. Output file
will be _target/release/tm_.

## (Possibly Breaking) notable changes compared to old shell version
While the rewrite is intended to be as much as possible compatible to
the shell variant from earlier, this is not entirely possible. Shell
*is* a bit different environment after all, and some things that work
there, for whatever reason, just don't work when using a compiled
binary now, as they depend on shell internal behaviour.

The folowing is a (possibly) incomplete list of known behaviour
changes.

### LIST commands using ssh possibly requiring pseudo-terminal
Some commands (eg. sudo can be configured for this) may require a
pseudo-terminal or they refuse work. Add `-tt` to the ssh commandline
to force allocation of one.

### LIST commands in simple config files
The LIST commands in simple config files need to be checked for
correct quoting. Example:

*Broken*
```
LIST ssh -tt TARGETHOST sudo /usr/sbin/gnt-instance list --no-headers -o name --filter '("nsb" in tags and "prod" in tags) and admin_state == "up"'
```
*Fixed*
```
LIST ssh -tt TARGETHOST "sudo /usr/sbin/gnt-instance list --no-headers -o name --filter '(\"nsb\" in tags and \"prod\" in tags) and admin_state == \"up\"'"
```
