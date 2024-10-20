//! tm - a tmux helper
//!
//! SPDX-License-Identifier: BSD-2-Clause
//!
//! Copyright (C) 2011-2024 Joerg Jaspert <joerg@debian.org>
//!
//! There are two ways to call tm. Traditional and "getopts" style.
//!
//! Traditional call as:
//! ```shell
//! tm CMD [host]...[host]
//! ```
//!
//! Getopts call as:
//! ```shell
//! tm [-s host] [-m hostlist] [-k name] [-l] [-n] [-h] [-c config] [-e]
//! ```
//!
//! Note that traditional and getopts can be mixed, sometimes.

#![warn(missing_docs)]

mod config;
#[macro_use]
mod fromenvstatic;
mod session;

use crate::config::{Cli, Commands};
use crate::session::Session;
use anyhow::{anyhow, Result};
use clap::Parser;
use directories::UserDirs;
use shlex::Shlex;
use std::{
    env,
    ffi::OsString,
    io::{self, BufWriter, Write},
    path::Path,
    process::Command,
    sync::LazyLock,
};
use tmux_interface::{ListSessions, NewSession, ShowOptions, Tmux};
use tracing::{debug, error, event, info, trace, warn, Level};
use tracing_subscriber::{fmt::time::ChronoLocal, FmtSubscriber};

////////////////////////////////////////////////////////////////////////

// A bunch of "static" variables, though computed at program start, as they
// depend on the users environment.
///  We want a useful tmpdir, so set one if it isn't already. That's
///  the place where tmux puts its socket, so you want to ensure it
///  doesn't change under your feet - like for those with a
///  daily-changing tmpdir in their home...
static TMPDIR: LazyLock<String> = LazyLock::new(|| fromenvstatic!(asString "TMPDIR", "/tmp"));

/// Do you want me to sort the arguments when opening an
/// ssh/multi-ssh session? The only use of the sorted list is for
/// the session name, to allow you to get the same session again no
/// matter how you order the hosts on commandline.
static TMSORT: LazyLock<bool> = LazyLock::new(|| fromenvstatic!(asBool "TMSORT", true));

/// Want some extra options given to tmux? Define TMOPTS in your
/// environment. Note, this is only used in the final tmux call
/// where we actually attach to the session!
static TMOPTS: LazyLock<String> = LazyLock::new(|| fromenvstatic!(asString "TMOPTS", "-2"));

/// The following directory can hold session config for us, so you
/// can use it as a shortcut.
static TMDIR: LazyLock<OsString> = LazyLock::new(|| {
    if let Some(user_dirs) = UserDirs::new() {
        Path::join(user_dirs.home_dir(), Path::new(".tmux.d")).into_os_string()
    } else {
        error!("No idea where your homedir is, using /tmp");
        Path::new("/tmp").as_os_str().to_owned()
    }
});

/// Prepend the hostname to autogenerated session names?
///
/// Example: Call `tm ms host1 host2`.
/// * TMSESSHOST=true  -> session name is `HOSTNAME_host1_host2`
/// * TMSESSHOST=false -> session name is `host1_host2`
static TMSESSHOST: LazyLock<bool> = LazyLock::new(|| fromenvstatic!(asBool "TMSESSHOST", false));

/// Allow to globally define a custom ssh command line.
static TMSSHCMD: LazyLock<String> = LazyLock::new(|| fromenvstatic!(asString "TMSSHCMD", "ssh"));

/// From where does tmux start numbering its windows. Old shell
/// script used a stupid way of config parsing or setting it via
/// environment var. We now just use show_options, and in the
/// unlikely case this fails, try parsing the old environment var
/// TMWIN, and if that doesn't exist (quite likely now), just use
/// 1.
// FIXME: This depends on a running tmux daemon. None running -> data fetching
// fails. Could fix to detect that and start one first, later killing that.
static TMWIN: LazyLock<u32> = LazyLock::new(|| {
    match Tmux::with_command(
        ShowOptions::new()
            .global()
            .quiet()
            .value()
            .option("base-index"),
    )
    .output()
    {
        Ok(v) => v.to_string().trim().parse().unwrap_or(1),
        Err(_) => fromenvstatic!(asU32 "TMWIN", 1),
    }
});

/// Run ls
///
/// Simply runs `tmux list-sessions`
#[tracing::instrument(level = "trace", skip(handle), ret, err)]
fn ls<W: Write>(handle: &mut BufWriter<W>) -> Result<()> {
    Ok(writeln!(
        handle,
        "{}",
        Tmux::with_command(ListSessions::new()).output()?
    )?)
}

/// Tiny helper to replace the magic ++TMREPLACETM++
#[doc(hidden)]
#[tracing::instrument(level = "trace", ret, err)]
fn tmreplace(input: &str, replace: &Option<String>) -> Result<String> {
    match replace {
        Some(v) => Ok(input.replace("++TMREPLACETM++", v)),
        None => Ok(input.to_string()),
    }
}

/// Parse a line of a simple_config file.
///
/// If a LIST command is found, execute that, and parse its output -
/// if that contains LIST again, recurse.
///
/// Return all found hostnames.
#[tracing::instrument(level = "trace", ret, err)]
fn parse_line(line: &str, replace: &Option<String>, current_dir: &Path) -> Result<Vec<String>> {
    // We are interested in the first word to decide what we see
    let first = line.split_whitespace().next();
    match first {
        // LIST, we are asked to execute something and read its stdout
        Some("LIST") => {
            debug!("LIST command found");
            // The rest of the line (command and arguments)
            let mut cmdparser = {
                let rest = line.trim_start_matches("LIST");
                debug!("Parsing command line: {:?}", rest);
                // Do a shell-conform split of the command and arguments,
                // ie take care of " and things.
                Shlex::new(rest)
            };

            // The command ought to be the second word on the line,
            // but obviously people may mistype and have a single LIST
            // in a line.
            // Also, ~ and $HOME/${HOME} expansion are supported.
            let cmd: String = shellexpand::full(
                &cmdparser
                    .next()
                    .ok_or_else(|| anyhow!("Empty LIST found - no command given"))?
                    .replace("$HOME", "~/")
                    .replace("${HOME}", "~/"),
            )?
            .to_string();
            // Next we want the arguments.
            // Also, ~ and $HOME/${HOME} expansion are supported.
            let args: Vec<String> = cmdparser
                .map(|l| l.replace("$HOME", "~/").replace("${HOME}", "~/"))
                .map(|l| shellexpand::full(&l).expect("Could not expand").to_string())
                .collect();
            debug!("cmd is {}", cmd);
            debug!("args are {:?}", args);

            // Our process spawner, pleased to hand us results as a nice
            // string separated by newline (well, if output contains newlines)
            let cmdout = String::from_utf8(
                Command::new(&cmd)
                    .current_dir(current_dir)
                    .args(&args)
                    .output()?
                    .stdout,
            )?;
            debug!("Command returned: {:?}", cmdout);
            if !cmdout.is_empty() {
                let mut plhosts: Vec<String> = Vec::new();
                for plline in cmdout.lines() {
                    trace!("Read line: '{}'", plline);
                    // Replace magic token, if exists and asked for
                    let plline = tmreplace(plline, replace)?;
                    debug!("Processing line: '{}'", plline);
                    // And process the line, may contain another command
                    // OR just a hostname
                    plhosts.append(&mut parse_line(&plline, replace, current_dir)?);
                }
                Ok(plhosts)
            } else {
                Err(anyhow!(
                    "LIST command {cmd} {args:?} produced no output, can not build session"
                ))
            }
        }
        Some(&_) => {
            trace!("SSH destination, returning");
            Ok(vec![line.to_string()])
        }
        None => {
            trace!("Empty line, ignoring");
            Ok(vec![])
        }
    }
}

static VERSION: &str = env!("CARGO_PKG_VERSION");
static APPLICATION: &str = env!("CARGO_PKG_NAME");

// Can't sensibly test main()
#[cfg(not(tarpaulin_include))]
/// main, start it all off
fn main() -> Result<()> {
    let cli = Cli::parse();
    let filter = cli.verbose.log_level_filter();
    let subscriberbuild = FmtSubscriber::builder()
        .with_max_level({
            match filter {
                log::LevelFilter::Off => tracing_subscriber::filter::LevelFilter::OFF,
                log::LevelFilter::Error => tracing_subscriber::filter::LevelFilter::ERROR,
                log::LevelFilter::Warn => tracing_subscriber::filter::LevelFilter::WARN,
                log::LevelFilter::Info => tracing_subscriber::filter::LevelFilter::INFO,
                log::LevelFilter::Debug => tracing_subscriber::filter::LevelFilter::DEBUG,
                log::LevelFilter::Trace => tracing_subscriber::filter::LevelFilter::TRACE,
            }
        })
        .with_ansi(true)
        .with_target(true)
        .with_file(true)
        .with_line_number(true)
        .with_timer(ChronoLocal::rfc_3339())
        .pretty();

    let subscriber = match filter {
        log::LevelFilter::Trace => subscriberbuild
            .with_span_events(
                tracing_subscriber::fmt::format::FmtSpan::ACTIVE
                    | tracing_subscriber::fmt::format::FmtSpan::CLOSE,
            )
            .finish(),
        _ => subscriberbuild
            .with_span_events(tracing_subscriber::fmt::format::FmtSpan::ACTIVE)
            .finish(),
    };

    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

    info!("Starting {APPLICATION}, version {VERSION}");
    event!(
        Level::DEBUG,
        msg = "Program started",
        cli = ?cli,
        TMPDIR = *TMPDIR,
        TMSORT = *TMSORT,
        TMOPTS =*TMOPTS,
        TMDIR = ?*TMDIR,
        TMSESSHOST = *TMSESSHOST,
        TMSSHCMD = *TMSSHCMD,
        TMWIN = *TMWIN,
    );

    let mut session = Session {
        ..Default::default()
    };

    // First get a session name
    let sesname = cli.find_session_name(&mut session)?;
    // Should, if we attach, this be grouped?
    if cli.group {
        session.grouped = true;
    }

    // Store the replacement token
    session.replace = cli.replace.clone();

    // First we check what the tm shell called "getopt-style"
    if cli.ls {
        let stdout = io::stdout();
        let mut handle = BufWriter::new(stdout.lock());
        ls(&mut handle)?;
        handle.flush()?;
    } else if cli.kill.is_some() {
        session.kill()?;
    } else if cli.session.is_some() || cli.config.is_some() {
        let sespath = if cli.session.is_some() {
            Path::join(Path::new(&*TMDIR), Path::new(&cli.session.clone().unwrap()))
        } else {
            Path::join(Path::new(&*TMDIR), Path::new(&cli.config.clone().unwrap()))
        };

        if Path::new(&sespath).exists() {
            trace!(
                "Should attach session {} or configure session from {:?}",
                sesname,
                sespath
            );
            session.sesfile = sespath;
            session.read_session_file_and_attach()?;
        } else {
            trace!("Should attach or create session {}", sesname);
            match session.attach() {
                Ok(true) => debug!("Successfully attached"),
                Ok(false) => {
                    debug!("Session not found, creating new one");
                    Tmux::with_command(NewSession::new().session_name(&session.name)).output()?;
                }
                Err(val) => error!("Error: {val}"),
            }
        };
    } else if cli.sshhosts.is_some() || cli.multihosts.is_some() {
        trace!("Session connecting somewhere");
        if session.exists() {
            session.attach()?;
        } else {
            if cli.sshhosts.is_some() {
                // sshhosts -> Multiple windows, not synced input
                session.synced = false;
            } else {
                // not sshhost, aka multihosts -> One window, many panes, synced input
                session.synced = true;
            }
            session.targets = cli.get_hosts()?;
            if session.setup_simple_session()? {
                session.attach()?;
            }
        }
    } else if cli.breakw.is_some() {
        trace!("Breaking up session");
        if session.exists() {
            session.break_panes()?;
        } else {
            info!("No session {} exists, can not break", session.name);
            println!("No session {sesname}");
        }
    } else if cli.joinw.is_some() {
        trace!("Joining session");
        if session.exists() {
            session.join_windows()?;
        } else {
            info!("No session {} exists, can not join", session.name);
            println!("No session {sesname}");
        }
    };

    // Now we check what the tm shell called traditional Yeah, this
    // can run things twice, e.g. if we are called as tm -l ls it will
    // show ls twice. But we want to be able to combine the two
    // styles, e.g. call as tm -n ms SOMETHING.
    // I bet there is a way to get rid of this double thing and merge
    // the above and the following, so:
    // FIXME: Merge the above if and the match here, somehow, dedupe
    // the code.
    if cli.command.is_some() {
        match &cli.command.as_ref().unwrap() {
            Commands::Ls {} => {
                let stdout = io::stdout();
                let mut handle = BufWriter::new(stdout.lock());
                ls(&mut handle)?;
                handle.flush()?;
            }
            Commands::S { hosts: _ } => {
                trace!("ssh subcommand called");
                if session.exists() {
                    session.attach()?;
                } else {
                    session.synced = false;
                    session.targets = cli.get_hosts()?;
                    session.setup_simple_session()?;
                    session.attach()?;
                }
            }
            Commands::Ms { hosts: _ } => {
                trace!("ms subcommand called");
                if session.exists() {
                    session.attach()?;
                } else {
                    session.synced = true;
                    session.targets = cli.get_hosts()?;
                    session.setup_simple_session()?;
                    session.attach()?;
                }
            }
            Commands::K { sesname } => {
                trace!("k subcommand called, killing {sesname}");
                session.kill()?;
            }
            Commands::B { sesname } => {
                trace!("b subcommand called, breaking panes into windows for {sesname}");
                if session.exists() {
                    session.break_panes()?;
                } else {
                    info!("No session {sesname} exists, can not break");
                    println!("No session {sesname}");
                }
            }
            Commands::J { sesname } => {
                trace!("j subcommand called, joining windows into panes for {sesname}");
                session.join_windows()?;
            }
        }
    }
    info!("All done, end");
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::{
        ls, parse_line, tmreplace, Session, TMOPTS, TMPDIR, TMSESSHOST, TMSORT, TMSSHCMD, TMWIN,
    };
    use std::{
        env,
        io::{BufWriter, Write},
        path::Path,
    };
    use tmux_interface::{NewSession, Tmux};

    #[test]
    fn test_fromenvstatic() {
        // Testing with env vars isn't nice - users may set them randomly.
        // So pre-define a known set, so we at least can test the code
        // around fromenvstatic
        env::set_var("TMPDIR", "/tmp");
        env::set_var("TMOPTS", "-2");
        env::set_var("TMSORT", "true");
        env::set_var("TMSESSHOST", "false");
        env::set_var("TMSSHCMD", "ssh");
        env::set_var("TMWIN", "1");
        assert_eq!(*TMPDIR, "/tmp");
        assert_eq!(*TMOPTS, "-2");
        assert!(*TMSORT);
        assert!(!*TMSESSHOST);
        assert_eq!(*TMSSHCMD, "ssh");
        assert_eq!(*TMWIN, 1);
    }

    #[test]
    fn test_attach() {
        let mut session = Session {
            ..Default::default()
        };
        // We want a new session
        session.set_name("fakeattach");
        // Shouldn't exist
        assert!(!session.exists());
        // Lets create it
        Tmux::with_command(
            NewSession::new()
                .session_name(&session.name)
                .detached()
                .shell_command("/bin/bash"),
        )
        .output()
        .unwrap();
        // Is it there?
        assert!(session.exists());
        // Now try the attach. if cfg!(test) code should just return true
        assert!(session.attach().unwrap());
        // Grouped sessions are nice
        session.grouped = true;
        // Try attach again
        assert!(session.attach().unwrap());
        // gsesname will contain session name plus random string
        // FIXME: Better check with a regex to be written
        assert_ne!(session.name, session.gsesname);
        println!("Grouped session name: {}", session.gsesname);
        // Get rid of session - this will remove the original one
        session.kill().unwrap();
        // FIXME: Check that it only removed the original one
        // Now get rid of the grouped session too.
        assert!(session.realkill(&session.gsesname).unwrap());

        assert!(!session.exists());
        // And now we test something that shouldn't work for attach
        session.set_name("notfakeattach");
        // Not grouped
        session.grouped = false;
        // Shouldn't exist
        assert!(!session.exists());
        // Lets create it
        Tmux::with_command(
            NewSession::new()
                .session_name(&session.name)
                .detached()
                .shell_command("/bin/bash"),
        )
        .output()
        .unwrap();
        // Is it there?
        assert!(session.exists());
        // Now try the attach. if cfg!(test) code should just return false here
        assert!(!session.attach().unwrap());
        // Get rid of session
        session.kill().unwrap();
    }

    #[test]
    fn test_kill_ls_and_exists() {
        let mut session = Session {
            ..Default::default()
        };
        session.set_name("tmtestsession");
        assert!(!session.exists());
        Tmux::with_command(
            NewSession::new()
                .session_name(&session.name)
                .detached()
                .shell_command("/bin/bash"),
        )
        .output()
        .unwrap();
        assert!(session.exists());

        // We want to check the output of ls contains our session from
        // above, so have it "write" it to a variable, then check if
        // the variable contains the session name.
        let lstext = Vec::new();
        let mut handle = BufWriter::new(lstext);
        ls(&mut handle).unwrap();
        handle.flush().unwrap();

        assert!(session.kill().unwrap());
        assert!(session.kill().is_err());
        assert!(!session.exists());

        // And now check what got "written" into the variable
        let (recovered_writer, _buffered_data) = handle.into_parts();
        let output = String::from_utf8(recovered_writer).unwrap();
        assert!(output.contains(&session.name));
    }

    #[test]
    fn test_tmreplace() {
        assert_eq!(tmreplace("test", &None).unwrap(), "test".to_string());
        assert_eq!(
            tmreplace("test", &Some("foo".to_string())).unwrap(),
            "test".to_string()
        );
        assert_eq!(
            tmreplace("test++TMREPLACETM++", &Some("foo".to_string())).unwrap(),
            "testfoo".to_string()
        );
    }

    #[test]
    fn test_parse_line() {
        let mut line = "justonehost";
        let mut replace = None;
        let mut current_dir = Path::new("/");
        let mut res = parse_line(line, &replace, current_dir).unwrap();
        assert_eq!(res, vec!["justonehost".to_string()]);
        line = "LIST /bin/echo \"onehost\ntwohost\nthreehost\"";
        replace = None;
        current_dir = Path::new("/");
        res = parse_line(line, &replace, current_dir).unwrap();
        assert_eq!(
            res,
            vec![
                "onehost".to_string(),
                "twohost".to_string(),
                "threehost".to_string()
            ]
        );
        line = "LIST /bin/echo \"onehost\ntwohost\nthreehost\nfoobar\nLIST /bin/echo \"LIST /bin/echo \"bar\nbaz\n\"\n\"\"";
        replace = None;
        current_dir = Path::new("/");
        res = parse_line(line, &replace, current_dir).unwrap();
        assert_eq!(
            res,
            vec![
                "onehost".to_string(),
                "twohost".to_string(),
                "threehost".to_string(),
                "foobar".to_string(),
                "bar".to_string(),
                "baz".to_string()
            ]
        );
        line = " ";
        replace = None;
        current_dir = Path::new("/");
        res = parse_line(line, &replace, current_dir).unwrap();
        let empty: Vec<String> = vec![];
        assert_eq!(res, empty);
    }
}
