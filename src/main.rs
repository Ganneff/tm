//! tm - a tmux helper
//!
//! SPDX-License-Identifier: BSD-2-Clause
//!
//! Copyright (C) 2011-2022 Joerg Jaspert <joerg@debian.org>
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

#[macro_use]
extern crate lazy_static;

use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use directories::UserDirs;
use flexi_logger::{AdaptiveFormat, Logger};
use log::{debug, error, info, trace};
use rand::Rng;
use std::{
    env,
    ffi::OsString,
    fs::File,
    io::{BufRead, BufReader},
    path::Path,
    process::Command,
    str::FromStr,
};
use tmux_interface::TmuxCommand;

#[derive(Debug, Parser)]
#[clap(author, version, about)]
#[clap(propagate_version = true)]
/// Options for tm, they are closely resembling (ought to be compatible) to the ones from the old shell script.
struct Cli {
    /// subcommands
    #[clap(subcommand)]
    command: Option<Commands>,

    /// List running sessions
    ///
    /// This is basically `tmux ls`
    #[clap(short, display_order = 10, takes_value = false)]
    ls: bool,

    /// Open SSH session to the destination
    ///
    /// The arguments are the destinations for `ssh(1)`, which may be
    /// specified as either \[user@]hostname or a URI of the form
    /// ssh://\[user@]hostname\[:port].
    ///
    /// When multiple destinations are specified, they are all opened
    /// into seperate tmux windows (not sessions!).
    #[clap(short = 's', display_order = 15, multiple_values = true)]
    sshhosts: Option<Vec<String>>,

    /// Open multi SSH sessions to hosts, synchronizing input.
    ///
    /// The same details for the arguments as for [Cli::sshhosts] applies.
    ///
    /// When multiple destinations are specified, they are all opened
    /// into one single tmux window and many panes in there.
    /// Additionally, the "synchronize-input" option is turned on, so
    /// that anything entered will be send to every host.
    #[clap(short = 'm', display_order = 20, multiple_values = true)]
    multihosts: Option<Vec<String>>,

    /// Open as second session to the same set of hosts as an existing
    /// one, instead of attaching to the existing
    ///
    /// This way more than one session to the same set can be opened
    /// and used.
    #[clap(short = 'n', display_order = 25)]
    second: bool,

    /// Group session - attach to an existing session, but keep
    /// seperate window config
    ///
    /// This will show the same set of windows, but allow different
    /// handling of the session according to client. This one client
    /// could display the first, another the second window. Without
    /// this option, a second client would always show the same
    /// content as the first.
    #[clap(short = 'g', display_order = 30)]
    group: Option<bool>,

    /// Kill a session, Session name as shown by ls
    #[clap(short = 'k', display_order = 35)]
    kill: Option<String>,

    /// Setup session according to file in TMDIR
    #[clap(short = 'c', display_order = 40)]
    config: Option<String>,

    /// Use existing session SESSION
    #[clap(short = 'e', display_order = 45)]
    exist: Option<String>,

    /// Value to use for replacing in session files (see their help)
    #[clap(short = 'r', display_order = 50)]
    replace: Option<String>,

    #[clap(flatten)]
    verbose: clap_verbosity_flag::Verbosity,

    /// Either plain tmux session name, or session/file found in TMDIR
    ///
    /// If this exists as a tmux session, it behaves like `tmux
    /// attach`. Otherwise it checks TMDIR for existance of a config
    /// file and will open a session as specified in there.
    #[clap(display_order = 55)]
    session: Option<String>,
}

#[derive(Subcommand, Debug, PartialEq)]
/// Holds list of subcommands in use for tm
enum Commands {
    /// List running sessions
    ///
    /// This is basically `tmux ls`
    #[clap(display_order = 10)]
    Ls {},

    /// Open SSH session to the destination
    ///
    /// When multiple destinations are specified, they are all opened
    /// into seperate tmux windows (not sessions!).
    #[clap(display_order = 15)]
    S {
        /// Target destinations for `ssh(1)`, which may be specified as
        /// either \[user@]hostname or a URI of the form
        /// ssh://\[user@]hostname\[:port].
        hosts: Vec<String>,
    },

    /// Open multi SSH sessions to hosts, synchronizing input.
    ///
    /// When multiple destinations are specified, they are all opened
    /// into one single tmux window and many panes in there.
    /// Additionally, the "synchronize-input" option is turned on, so
    /// that anything entered will be send to every host.
    #[clap(display_order = 20)]
    Ms {
        /// List of target destinations for `ssh(1)`, the same details
        /// for the arguments as for [Cli::sshhosts] applies.
        hosts: Vec<String>,
    },

    /// Kill a session
    #[clap(display_order = 25)]
    K {
        /// Session name as shown by ls to kill, same as [Session](Cli::kill)
        sesname: String,
    },
}

/// Some additional functions for Cli, to make our life easier
impl Cli {
    /// Return a session name
    ///
    /// This checks
    /// - [struct@TMSORT], to maybe sort the hostnames,
    /// - the [Cli::second] option, to maybe add a random number in
    /// the range of [u16] using [rand::thread_rng].
    ///
    /// It also "cleans" the session name, that is, it replaces
    /// spaces, :, " and . with _ (underscores).
    fn session_name(&self) -> Result<String> {
        trace!("In session_name");
        let mut hosts = self.get_hosts()?;
        trace!(
            "Need to build session name from: {:?}, TMSESSHOST: {}",
            hosts,
            *TMSESSHOST
        );

        if *TMSORT {
            hosts.sort();
        }
        hosts.insert(0, self.get_insert());

        if self.second {
            let mut rng = rand::thread_rng();
            let insert: u16 = rng.gen();
            trace!(
                "Second session wanted, inserting {} into session name",
                insert
            );
            hosts.insert(1, insert.to_string());
        }
        // Replace a set of characters we do not want in the session name with _
        let name = { hosts }.join("_").replace(&[' ', ':', '"', '.'][..], "_");
        debug!("Generated session name: {}", name);
        Ok(name)
    }

    /// Returns a string depending on subcommand called, to adjust
    /// session name with.
    fn get_insert(&self) -> String {
        match &self.sshhosts {
            Some(_) => "s".to_string(),
            None => match &self.multihosts {
                Some(_) => "ms".to_string(),
                None => match &self.command.as_ref().unwrap() {
                    Commands::S { hosts: _ } => 's'.to_string(),
                    Commands::Ms { hosts: _ } => "ms".to_string(),
                    &_ => "".to_string(),
                },
            },
        }
    }

    /// Return a hostlist.
    ///
    /// The list can either be from the s or ms command.
    fn get_hosts(&self) -> Result<Vec<String>> {
        match &self.sshhosts {
            Some(v) => Ok(v.to_vec()),
            None => match &self.multihosts {
                Some(v) => Ok(v.to_vec()),
                None => match &self.command.as_ref().unwrap() {
                    Commands::S { hosts } | Commands::Ms { hosts } => Ok(hosts.clone()),
                    &_ => Err(anyhow!("No hosts supplied, can not get any")),
                },
            },
        }
    }
}

/// Help setting up static variables based on user environment.
///
/// We allow the user to configure certain properties/behaviours of tm
/// using environment variables. To reduce boilerplate in code, we use a
/// macro for setting them. We use [mod@`lazy_static`] to define them as
/// global variables, so they are available throughout the whole program -
/// they aren't going to change during runtime, ever, anyways.
///
/// # Examples
///
/// ```
/// # fn main() {
/// static ref TMPDIR: String = fromenvstatic!(asString "TMPDIR", "/tmp");
/// static ref TMSORT: bool = fromenvstatic!(asBool "TMSORT", true);
/// static ref TMWIN: u8 = fromenvstatic!(asU8 "TMWIN", 1);
/// # }
/// ```
macro_rules! fromenvstatic {
    (asString $envvar:literal, $default:expr) => {
        match env::var($envvar) {
            Ok(val) => val,
            Err(_) => $default.to_string(),
        }
    };
    (asBool $envvar:literal, $default:literal) => {
        match env::var($envvar) {
            Ok(val) => FromStr::from_str(&val).unwrap(),
            Err(_) => $default,
        }
    };
    (asU8 $envvar:literal, $default:literal) => {
        match env::var($envvar) {
            Ok(val) => val.parse::<u8>().unwrap(),
            Err(_) => $default,
        }
    };
}

/// Set an option for a tmux window
///
/// tmux windows can have a large set of options attached. We do
/// regularly want to set some.
///
/// # Example
/// ```
/// # fn main() {
/// setwinopt!(sesname, windowindex, "automatic-rename", "off");
/// # }
/// ```
macro_rules! setwinopt {
    ($sesname:expr, $index:tt, $option: literal, $value:literal) => {
        let tar = format!("{}:{}", &$sesname, $index);
        trace!("Setting Window ({}) option {} to {}", tar, $option, $value);
        match TmuxCommand::new()
            .set_option()
            .window()
            .target(&tar)
            .option($option)
            .value($value)
            .output()
        {
            Ok(_) => trace!("Window option successfully set"),
            Err(error) => {
                debug!("Error setting window option {}: {:#?}", $option, error);
            }
        }
    };
}

/// Attach to an existing session
macro_rules! attach_session {
    ($sesname:expr) => {
        match attach($sesname) {
            Ok(true) => debug!("Successfully attached to {}", $sesname),
            Ok(false) => debug!("Session {} not found, could not attach", $sesname),
            Err(val) => error!("Error: {}", val),
        }
    };
    ($sesname:expr, $func:expr) => {
        match attach($sesname) {
            Ok(true) => debug!("Successfully attached to {}", $sesname),
            Ok(false) => {
                debug!(
                    "Session {} not found, going to set it up from scratch",
                    $sesname
                );
                match $func {
                    Ok(_) => debug!("Successfully setup new session"),
                    Err(val) => error!("Error: {}", val),
                }
            }
            Err(val) => {
                error!("Error: {}", val);
            }
        };
    };
}

/// New tmux session, with a shell executing the command given
///
/// Parameters:
/// * `$host` SSH Destination for first window/pane in the new session, will be name of first window/pane
/// * `$sesname` Session name for tmux
/// * `$shellcommand` Actual command to execute
///
/// # Example
/// ```
/// newtmuxsession!("host.example.com", "example", format!("{} {}", *TMSSHCMD, "host.example.com"));
/// ```
macro_rules! newtmuxsession {
    ($host:expr, $sesname:expr, $shellcommand:expr) => {
        trace!("Open Session to {}", $host);
        TmuxCommand::new()
            .new_session()
            .detached()
            .session_name($sesname)
            .window_name($host)
            .shell_command($shellcommand)
            .output()?;
    };
}

// A bunch of "static" variables, though computed at program start, as they
// depend on the users environment.
lazy_static! {
    ///  We want a useful tmpdir, so set one if it isn't already. Thats
    ///  the place where tmux puts its socket, so you want to ensure it
    ///  doesn't change under your feet - like for those with a
    ///  daily-changing tmpdir in their home...
    static ref TMPDIR: String = fromenvstatic!(asString "TMPDIR", "/tmp");

    /// Do you want me to sort the arguments when opening an
    /// ssh/multi-ssh session? The only use of the sorted list is for
    /// the session name, to allow you to get the same session again no
    /// matter how you order the hosts on commandline.
    static ref TMSORT: bool = fromenvstatic!(asBool "TMSORT", true);

    /// Want some extra options given to tmux? Define TMOPTS in your
    /// environment. Note, this is only used in the final tmux call
    /// where we actually attach to the session!
    static ref TMOPTS: String = fromenvstatic!(asString "TMOPTS", "-2");

    /// The following directory can hold session config for us, so you
    /// can use it as a shortcut.
    static ref TMDIR: OsString = if let Some(user_dirs) = UserDirs::new() {
        Path::join(
            user_dirs.home_dir(),
            Path::new(".tmux.d"))
        .into_os_string()
    } else {
        error!("No idea where your homedir is, using /tmp");
        Path::new("/tmp").as_os_str().to_owned()
    };

    /// Prepend the hostname to autogenerated session names?
    ///
    /// Example: Call `tm ms host1 host2`.
    /// * TMSESSHOST=true  -> session name is `HOSTNAME_host1_host2`
    /// * TMSESSHOST=false -> session name is `host1_host2`
    static ref TMSESSHOST: bool = fromenvstatic!(asBool "TMSESSHOST", false);

    /// Allow to globally define a custom ssh command line.
    static ref TMSSHCMD: String = fromenvstatic!(asString "TMSSHCMD", "ssh");

    /// From where does tmux start numbering its windows. Old shell
    /// script used a stupid way of config parsing or setting it via
    /// environment var. We now just use show_options, and in the
    /// unlikely case this fails, try parsing the old environment var
    /// TMWIN, and if that doesn't exist (quite likely now), just use
    /// 1.
    // FIXME: This depends on a running tmux daemon. None running -> data fetching
    // fails. Could fix to detect that and start one first, later killing that.
    static ref TMWIN: u8 = match TmuxCommand::new()
        .show_options()
        .global()
        .quiet()
        .value()
        .option("base-index")
        .output()
    {
        Ok(v) => v.to_string().trim().parse().unwrap_or(1),
        Err(_) => fromenvstatic!(asU8 "TMWIN", 1),
    };
}

/// Run ls
///
/// Simply runs `tmux list-sessions`
fn ls() {
    trace!("Entering ls");
    let sessions = TmuxCommand::new()
        .list_sessions()
        .output()
        .unwrap()
        .to_string();
    println!("{}", sessions);
    trace!("Leaving ls");
}

/// Check if a session exists
fn has_session(session: &String) -> bool {
    TmuxCommand::new()
        .has_session()
        .target_session(session)
        .output()
        .unwrap()
        .0
        .status
        .success()
}

/// Attach to a running (or just prepared) tmux session
fn attach(session: &String) -> Result<bool, tmux_interface::Error> {
    trace!("Entering attach");
    let ret = if has_session(session) {
        TmuxCommand::new()
            .attach_session()
            .target_session(session)
            .output()?;
        true
    } else {
        false
    };
    trace!("Leaving attach with result {}", ret);
    Ok(ret)
}

/// SSH to multiple hosts, synchronized input (all panes receive the
/// same keystrokes)
fn syncssh(hosts: Vec<String>, sesname: &String) -> Result<&String, tmux_interface::Error> {
    trace!("Entering syncssh");
    debug!("Hosts to connect to: {:?}", hosts);
    debug!("Creating session {}", sesname);

    newtmuxsession!(&hosts[0], sesname, format!("{} {}", *TMSSHCMD, &hosts[0]));

    // Which window are we at? Start with TMWIN, later on count up (if
    // we open more than one)
    let wincount = *TMWIN;
    setwinopt!(sesname, wincount, "automatic-rename", "off");
    setwinopt!(sesname, wincount, "allow-rename", "off");

    // Next check if there was more than one host, if so, open windows
    // for them too.
    if hosts.len() >= 2 {
        debug!("Got more than 1 host, opening more panes with ssh sessions");
        let mut others = hosts.into_iter();
        // Skip the first, we already opened a connection
        others.next();
        for x in others {
            let mut count = 1;
            loop {
                debug!("New pane, session going to {}", x);
                let output = TmuxCommand::new()
                    .split_window()
                    .detached()
                    .target_window(sesname)
                    .shell_command(format!("{} {}", *TMSSHCMD, &x))
                    .output()
                    .unwrap();

                trace!("New pane: {:?}", output);
                if output.0.status.success() {
                    // Exit the loop, we made it and got the window
                    debug!("Pane opened successfully");
                    break;
                } else {
                    // Didn't work, lets help tmux along and then retry this
                    debug!("split-window did not work");
                    if count >= 3 {
                        error!(
                            "Could not successfully create another pane for {}, tried {} times",
                            x, count
                        );
                        break;
                    };
                    count += 1;

                    let reason: String = String::from_utf8(output.0.stderr)
                        .expect("Could not parse tmux fail reason");

                    debug!("Failure reason: {}", reason.trim());
                    if reason.trim().eq_ignore_ascii_case("no space for new pane") {
                        debug!("Panes getting too small, need to adjust layout");
                        // No space for new pane -> redo the layout so windows are equally sized again
                        let out = TmuxCommand::new()
                            .select_layout()
                            .layout_name("main-horizontal")
                            .output()
                            .expect("Could not spread out layout");
                        trace!("Layout result: {:#?}", out);
                    };
                };
            }
        }
    }
    // Now synchronize their input
    let firstwin = *TMWIN;
    setwinopt!(sesname, firstwin, "synchronize-pane", "on");
    // And select a final layout that all of them have roughly the same size
    if TmuxCommand::new()
        .select_layout()
        .layout_name("tiled")
        .output()
        .unwrap()
        .0
        .status
        .success()
    {
        trace!("syncssh successful");
        Ok(sesname)
    } else {
        trace!("syncssh failed");
        Err(tmux_interface::Error::Tmux(
            "Setting layout failed".to_owned(),
        ))
    }
}

/// SSH to a remote host (or multiple)
fn ssh(hosts: Vec<String>, sesname: &String) -> Result<&String, tmux_interface::Error> {
    trace!("Entering ssh");
    debug!("Creating session {}", sesname);
    debug!("Hosts to connect to: {:?}", hosts);

    newtmuxsession!(&hosts[0], sesname, format!("{} {}", *TMSSHCMD, &hosts[0]));
    // Which window are we at? Start with TMWIN, later on count up (if
    // we open more than one)
    let mut wincount = *TMWIN;
    setwinopt!(sesname, wincount, "automatic-rename", "off");
    setwinopt!(sesname, wincount, "allow-rename", "off");

    // Next check if there was more than one host, if so, open windows
    // for them too.
    if hosts.len() >= 2 {
        debug!("Got more than 1 host, opening more windows/ssh sessions");
        let mut others = hosts.into_iter();
        // Skip the first, we already had it
        others.next();
        for x in others {
            wincount += 1;
            debug!("Opening window for {}", &x);
            match TmuxCommand::new()
                .new_window()
                .detached()
                .add()
                .window_name(&x)
                .target_window(sesname)
                .shell_command(format!("{} {}", *TMSSHCMD, &x))
                .output()
            {
                Ok(_) => {
                    debug!("Window/Pane {} opened", wincount);
                    setwinopt!(sesname, wincount, "automatic-rename", "off");
                    setwinopt!(sesname, wincount, "allow-rename", "off");
                }
                Err(output) => {
                    return Err(output);
                }
            }
        }
    }
    trace!("Leaving ssh");
    Ok(sesname)
}

/// Kill a session
fn kill_session(sesname: &String) {
    trace!("Entering kill_session");
    if has_session(sesname) {
        debug!("Asked to kill session {}", sesname);
        if TmuxCommand::new()
            .kill_session()
            .target_session(sesname)
            .output()
            .unwrap()
            .0
            .status
            .success()
        {
            info!("Session {} is no more", &sesname);
        } else {
            info!("Session {} could not be killed!", &sesname);
        }
    } else {
        debug!("No such session {}", &sesname);
    }
}

/// Tiny helper to replace the magic ++TMREPLACETM++
#[doc(hidden)]
fn tmreplace(input: &String, replace: &Option<String>) -> Result<String> {
    match replace {
        Some(v) => Ok(input.replace("++TMREPLACETM++", v)),
        None => Ok(input.to_string()),
    }
}

/// Parse a line of a [simple_config] file.
///
/// If a LIST command is found, execute that, and parse its output -
/// if that contains LIST again, recurse.
///
/// Return all found hostnames.
fn parse_line(line: &str, replace: &Option<String>, current_dir: &Path) -> Result<Vec<String>> {
    trace!("Entered parse_line");
    // We are interested in the first word to decide what we see
    let mut splitit = line.split_ascii_whitespace();
    match splitit.next() {
        // LIST, we are asked to execute something and read its stdout
        Some("LIST") => {
            debug!("LIST command found");
            // The command ought to be the second word on the line,
            // but obviously people may mistype and have a single LIST
            // in a line.
            let cmd = splitit
                .next()
                .ok_or(anyhow!("Empty LIST found - no command given"))?;
            // And all the rest, whatever there may be, is arguments for command.
            let args = splitit.collect::<Vec<&str>>();
            debug!("cmd is {}", cmd);
            debug!("args are {:?}", args);
            // Our process spawner, pleased to hand us results as a nice
            // string seperated by newline (well, if output contains newlines)
            let cmdout = String::from_utf8(
                Command::new(cmd)
                    .current_dir(&current_dir)
                    .args(args)
                    .output()?
                    .stdout,
            )?;
            debug!("Command returned: {:?}", cmdout);
            let mut plhosts: Vec<String> = Vec::new();
            for plline in cmdout.lines() {
                trace!("Read line: '{}'", plline);
                // Replace magic token, if exists and asked for
                let plline = tmreplace(&plline.to_string(), replace)?;
                debug!("Processing line: '{}'", plline);
                // And process the line, may contain another command
                // OR just a hostname
                plhosts.append(&mut parse_line(&plline, replace, current_dir)?);
            }
            Ok(plhosts)
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

/// Create a new session from a "simple" config file.
///
/// This will create a new tmux session according to the _simple_
/// style config file found at `sesfile`. The format of those files is a
/// simple line based one, with the following properties:
///
/// 1. Session name
/// 1. Extra tmux command line options, most commonly **NONE**. _(currently options are unsupported in the rust tm version)_
/// 1. Either an SSH destination (\[user@]hostname) **or** the LIST command.
/// 1. [...] As many SSH destinations/LIST commands as wanted and needed.
///
/// # SSH destination
/// Taken from the ssh(1) manpage:
/// ssh connects and logs into the specified destination, which may be
/// specified as either \[user@]hostname or a URI of the form
/// ssh://\[user@]hostname\[:port].
///
/// # LIST command
/// Instead of an SSH destination, the command **LIST** followed by an
/// argument is also accepted. The argument must be a runnable command
/// that outputs a list of SSH destinations on stdout and exits
/// successfully.
///
/// The command will be run in the same directory the simple config
/// file is found in.
///
/// **Note**: This is recursive, so if output of a command contains
/// **LIST** again, it will also be executed and its output used.
/// There is no limit (except stack size) on recursion, so yes, you
/// can build a loop and then watch tm race to a panic..
///
/// # Example
/// The following will open a tmux session named `examplesession`, connection to two hosts.
/// ```
/// examplesession
/// NONE
/// ganneff@host1
/// user@host2
/// ```
///
/// The following will open a tmux session `anotherexample`,
/// connecting to at least one host, but possibly more, depending on
/// how many lines of SSH destinations the `cat foo.list` command will
/// print to stdout.
/// ```
/// anotherexample
/// NONE
/// ganneff@host3
/// LIST cat foo.list
/// ```
fn simple_config(sesfile: &Path, replace: &Option<String>) -> Result<()> {
    trace!("Entered simple_config, for session file: {:?}", sesfile);
    // Needed for parse_line, to set directory for processes it may spawn
    let sesfilepath = sesfile.parent().ok_or(anyhow!(
        "Could not determine directory for {}",
        sesfile.display()
    ))?;
    // Want to read the session config file
    let sesreader = BufReader::new(File::open(sesfile)?);
    // Need session name later, default to Unknown, just in case
    let mut sesname: String = "Unknown".to_owned();
    // Hosts, default to empty list
    let mut hosts: Vec<String> = vec![];
    // Loop over all lines in session file, index is nice to see in
    // logs but much more important in match later
    for (index, line) in sesreader.lines().enumerate() {
        trace!("Read line {}: {:?}", index + 1, line);
        // Replace token, if exists
        let line = tmreplace(&line?, replace)?;
        debug!("Processing line {}: '{}'", index + 1, line);
        // Action to come depends on line we read
        match index {
            0 => {
                // First line is session name
                debug!("Session name: {}", &line);
                // Before we got to simple_config(), we already tried
                // looking for a session with the name the user gave
                // us as argument. And it did not exist.
                //
                // Unlucky us, this first line may NOT be the same as
                // that session name. So we check again, and if a
                // session name like this already exists, we error
                // out. Could, *maybe* attach to that? Unsure. Might
                // be surprising.
                if has_session(&line) {
                    return Err(anyhow!(
                        "Session name {} from file {:?} matches existing session, not recreating/messing with it.",
                        line,
                        sesfile
                    ));
                } else {
                    sesname = line.clone();
                }
            }
            1 => trace!("Ignoring 2nd line"),
            _ => {
                debug!("Hostname/LIST line");
                // Third and following lines are either hostnames or
                // LIST commands, so parse them.
                hosts.append(&mut parse_line(&line, replace, &sesfilepath)?);
            }
        }
    }
    trace!("Finished parsing session file");
    // We have a nice set of hosts and a session name, lets set it all up
    match syncssh(hosts, &sesname) {
        Ok(val) => {
            trace!("Session opened ({:#?}), now attaching", val);
            attach_session!(val);
            Ok(())
        }
        Err(val) => return Err(anyhow!("Could not finish session setup: {}", val)),
    }
}

/// main, start it all off
fn main() -> Result<()> {
    let cli = Cli::parse();
    Logger::try_with_env_or_str(cli.verbose.log_level_filter().as_str())
        .unwrap()
        .adaptive_format_for_stderr(AdaptiveFormat::Opt)
        .set_palette("b1;3;2;4;6".to_owned())
        .start()
        .unwrap();

    trace!("Program started");
    debug!("Cli options: {:#?}", cli);
    debug!("TMPDIR: {}", *TMPDIR);
    debug!("TMSORT: {}", *TMSORT);
    debug!("TMOPTS: {}", *TMOPTS);
    debug!("TMDIR: {:?}", *TMDIR);
    debug!("TMSESSHOST: {}", *TMSESSHOST);
    debug!("TMSSHCMD: {}", *TMSSHCMD);
    debug!("TMWIN: {}", *TMWIN);

    // First we check what the tm shell called "getopt-style"
    if cli.ls {
        ls();
    } else if cli.kill.is_some() {
        let sesname = cli.kill.as_ref().unwrap();
        kill_session(sesname);
    } else if cli.session.is_some() {
        let sesname = cli.session.as_ref().unwrap();
        let sespath = Path::join(Path::new(&*TMDIR), Path::new(sesname));
        if Path::new(&sespath).exists() {
            trace!(
                "Should attach session {} or configure session from {:?}",
                sesname,
                sespath
            );
            attach_session!(sesname, simple_config(&sespath, &cli.replace));
        } else {
            trace!("Should attach session {}", sesname);
            attach_session!(sesname);
        };
    } else if cli.sshhosts != None {
        trace!("ssh called");
        let sesname = &cli.session_name()?;
        if has_session(sesname) {
            attach_session!(sesname);
        } else {
            match ssh(cli.get_hosts()?, sesname) {
                Ok(val) => {
                    trace!("Session opened ({:#?}), now attaching", val);
                    attach_session!(val);
                }
                Err(val) => error!("Could not finish session setup: {}", val),
            }
        }
    } else if cli.multihosts != None {
        trace!("ms called");
        let sesname = &cli.session_name()?;
        if has_session(sesname) {
            attach_session!(sesname);
        } else {
            match syncssh(cli.get_hosts()?, sesname) {
                Ok(val) => {
                    trace!("Session opened ({:#?}), now attaching", val);
                    attach_session!(val);
                }
                Err(val) => error!("Could not finish session setup: {}", val),
            }
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
    if cli.command != None {
        match &cli.command.as_ref().unwrap() {
            Commands::Ls {} => ls(),
            Commands::S { hosts: _ } => {
                trace!("ssh called");
                let sesname = &cli.session_name()?;
                if has_session(sesname) {
                    attach_session!(sesname);
                } else {
                    match ssh(cli.get_hosts()?, sesname) {
                        Ok(val) => {
                            trace!("Session opened ({:#?}), now attaching", val);
                            attach_session!(val);
                        }
                        Err(val) => error!("Could not finish session setup: {}", val),
                    }
                }
            }
            Commands::Ms { hosts: _ } => {
                trace!("ms called");
                let sesname = &cli.session_name()?;
                if has_session(sesname) {
                    attach_session!(sesname);
                } else {
                    match syncssh(cli.get_hosts()?, sesname) {
                        Ok(val) => {
                            trace!("Session opened ({:#?}), now attaching", val);
                            attach_session!(val);
                        }
                        Err(val) => error!("Could not finish session setup: {}", val),
                    }
                }
            }
            Commands::K { sesname } => {
                kill_session(sesname);
            }
        }
    }
    info!("All done, end");
    Ok(())
}