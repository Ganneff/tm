# tm - tmux manager / helper

This is the second version of my tmux helper _tm_, used to ease my
day-to-day work with [tmux](https://github.com/tmux/tmux/wiki).
It is a rewrite in Rust, as I want to learn more Rust. Accidently that
made it much faster too, which is nice.

The rewrite is intended to be, as much as possible, a drop-in
replacement for the old shell version, so any usual _tm s_ or _tm ms_
usage should work right away, as well as the usual config files (see
status for how much is implemented).

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
