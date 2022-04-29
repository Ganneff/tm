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
use enum_default::EnumDefault;
use flexi_logger::{AdaptiveFormat, Logger};
use home_dir::HomeDirExt;
use itertools::Itertools;
use log::{debug, error, info, trace};
use rand::Rng;
use shlex::Shlex;
use std::{
    env,
    ffi::{OsStr, OsString},
    fs::File,
    io::{self, BufRead, BufReader, BufWriter, Write},
    path::{Path, PathBuf},
    process::Command,
    str::FromStr,
};
use tmux_interface::TmuxCommand;

#[derive(Debug, Parser)]
#[clap(author, version, about)]
#[clap(propagate_version = true)]
#[clap(arg_required_else_help = true)]
#[clap(dont_collapse_args_in_usage = true)]
/// Options for tm, they are closely resembling (ought to be compatible to) the ones from the old shell script.
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
    #[clap(
        short = 's',
        display_order = 15,
        multiple_values = true,
        min_values = 1
    )]
    sshhosts: Option<Vec<String>>,

    /// Open multi SSH sessions to hosts, synchronizing input.
    ///
    /// The same details for the arguments as for [Cli::sshhosts] applies.
    ///
    /// When multiple destinations are specified, they are all opened
    /// into one single tmux window with many panes in there.
    /// Additionally, the "synchronize-input" option is turned on, so
    /// that anything entered will be send to every host.
    #[clap(
        short = 'm',
        display_order = 20,
        multiple_values = true,
        min_values = 1
    )]
    multihosts: Option<Vec<String>>,

    /// Open as second session to the same set of hosts as an existing
    /// one, instead of attaching to the existing
    ///
    /// This way more than one session to the same set of ssh
    /// destinations can be opened and used.
    #[clap(short = 'n', display_order = 25)]
    second: bool,

    /// Group session - attach to an existing session, but keep
    /// seperate window config
    ///
    /// This will show the same set of windows, but allow different
    /// handling of the session according to client. This way one
    /// client could display the first, another the second window.
    /// Without this option, a second client would always show the
    /// same content as the first.
    #[clap(short = 'g', display_order = 30)]
    group: bool,

    /// Kill a session, Session name as shown by ls
    #[clap(short = 'k', display_order = 35)]
    kill: Option<String>,

    /// Setup session according to config file in TMDIR
    #[clap(short = 'c', display_order = 40)]
    config: Option<String>,

    #[clap(flatten)]
    verbose: clap_verbosity_flag::Verbosity,

    /// Either plain tmux session name, or session/file found in TMDIR
    ///
    /// If this exists as a tmux session, it behaves like `tmux
    /// attach`. Otherwise it checks TMDIR for existance of a config
    /// file and will open a session as specified in there.
    #[clap(display_order = 50)]
    session: Option<String>,

    /// Value to use for replacing in session files (see their help)
    #[clap(display_order = 55)]
    replace: Option<String>,
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
        #[clap(multiple_values = true, required = true)]
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
        #[clap(multiple_values = true, required = true)]
        hosts: Vec<String>,
    },

    /// Kill a session
    #[clap(display_order = 25)]
    K {
        /// Session name as shown by ls to kill, same as [Session](Cli::kill)
        #[clap(required = true)]
        sesname: String,
    },

    /// Break a multi-session pane into single windows
    #[clap(display_order = 30)]
    B {
        /// Sessiion name for which to break panes into windows
        #[clap(required = true)]
        sesname: String,
    },

    /// Join multiple windows into one single one with many panes
    #[clap(display_order = 35)]
    J {
        /// Sessiion name for which to join windows into panes
        #[clap(required = true)]
        sesname: String,
    },
}

////////////////////////////////////////////////////////////////////////
// Macros
////////////////////////////////////////////////////////////////////////
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
/// static ref TMWIN: u8 = fromenvstatic!(asU32 "TMWIN", 1);
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
    (asU32 $envvar:literal, $default:literal) => {
        match env::var($envvar) {
            Ok(val) => val.parse::<u32>().unwrap(),
            Err(_) => $default,
        }
    };
}

////////////////////////////////////////////////////////////////////////

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
    fn session_name_from_hosts(&self) -> Result<String> {
        trace!("In session_name_from_hosts");
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
        let name = hosts.join("_");
        debug!("Generated session name: {}", name);
        Ok(name)
    }

    /// Find (and set) a session name. Appears we have many
    /// possibilities to get at one, depending how we are called.
    fn find_session_name(&self, session: &mut Session) -> Result<String> {
        trace!("find_session_name");
        let possiblename: String = {
            if self.kill.is_some() {
                self.kill.clone().unwrap()
            } else if self.session.is_some() {
                self.session.clone().unwrap()
            } else if self.sshhosts != None || self.multihosts != None {
                self.session_name_from_hosts()?
            } else if self.command != None {
                match &self.command.as_ref().unwrap() {
                    Commands::S { hosts: _ } | Commands::Ms { hosts: _ } => {
                        self.session_name_from_hosts()?
                    }
                    Commands::K { sesname } | Commands::B { sesname } | Commands::J { sesname } => {
                        sesname.to_string()
                    }
                    &_ => "Unknown".to_string(),
                }
            } else {
                "Unhandled command so unknown session name".to_string()
            }
        };
        let sesname = session.set_name(&possiblename)?;
        Ok(sesname.to_string())
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

#[derive(EnumDefault, Debug)]
/// Possible Session types
enum SessionType {
    #[default]
    /// Simple - 2 initial lines, followed by 1 to many SSH destinations
    Simple,
    /// Extended - 2 initial lines, followed by 1 to many tmux commands
    Extended,
}

#[derive(Debug, Default)]
/// Store session related information
struct Session {
    /// The session name
    sesname: String,
    /// Should this be "grouped" - shares the same set of windows, new
    /// windows are linked to all sessions in the group, any window
    /// closed is removed from all sessions. But sessions are
    /// seperate, as are their current/previous window and session
    /// options.
    grouped: bool,
    /// The path to a session file
    sesfile: PathBuf,
    /// Type of session (file), from extension of file
    sestype: SessionType,
    /// Synchronized session? (Synchronized - input goes to all visible panes in tmux at once)
    synced: bool,
    /// List of SSH Destinations / commands for the session
    targets: Vec<String>,
    /// Token for the string replacement in session files
    replace: Option<String>,
}

impl Session {
    /// Takes a string, applies some cleanup, then stores it as
    /// session name, returning the cleaned up value
    fn set_name(&mut self, newname: &str) -> Result<&String> {
        trace!("Session.set_name(), input: {}", newname);
        // Replace a set of characters we do not want in the session name with _
        self.sesname = newname.replace(&[' ', ':', '"', '.'][..], "_");
        trace!("Session name now: {}", self.sesname);
        Ok(&self.sesname)
    }

    /// Kill a session
    fn kill(&self) -> Result<bool> {
        trace!("Session.kill()");
        if self.exists() {
            debug!("Asked to kill session {}", self.sesname);
            if TmuxCommand::new()
                .kill_session()
                .target_session(&self.sesname)
                .output()
                .unwrap()
                .0
                .status
                .success()
            {
                info!("Session {} is no more", self.sesname);
                Ok(true)
            } else {
                info!("Session {} could not be killed!", self.sesname);
                Err(anyhow!("Session {} could not be killed!", self.sesname))
            }
        } else {
            debug!("No such session {}", self.sesname);
            Err(anyhow!("No such session {}", self.sesname))
        }
    }

    /// Check if a session exists
    fn exists(&self) -> bool {
        TmuxCommand::new()
            .has_session()
            .target_session(&self.sesname)
            .output()
            .unwrap()
            .0
            .status
            .success()
    }

    /// Attach to a running (or just prepared) tmux session
    fn attach(&mut self) -> Result<bool> {
        trace!("Entering attach()");
        let ret = if self.exists() {
            if self.grouped {
                let mut rng = rand::thread_rng();
                let insert: u16 = rng.gen();
                let oldsesname = self.sesname.clone();
                self.sesname = format!("{}_{}", insert, oldsesname);
                debug!(
                    "Grouped session wanted, setting new session {}, linking it with {}",
                    self.sesname, oldsesname
                );

                TmuxCommand::new()
                    .new_session()
                    .session_name(&self.sesname)
                    .group_name(&oldsesname)
                    .output()?;
                info!(
                    "Removing grouped session {} (not the original!)",
                    &self.sesname
                );
                self.kill()?;
                true
            } else {
                TmuxCommand::new()
                    .attach_session()
                    .target_session(&self.sesname)
                    .output()?;
                true
            }
        } else {
            false
        };
        trace!("Leaving attach with result {}", ret);
        Ok(ret)
    }

    /// Read and parse a session file, run an action to create the session, then attach to it.
    ///
    /// This will create a new tmux session according to the session file, either a _simple_ or an _extended_
    /// style config file found at `sesfile`.
    ///
    /// # Config file formats
    /// ## Simple
    /// The _simple_ config style is a line based one, with the following properties:
    ///
    /// 1. Session name
    /// 1. Extra tmux command line options, most commonly **NONE**. _(currently options are unsupported in the rust tm version)_
    /// 1. Either an SSH destination (\[user@]hostname) **or** the LIST command.
    /// 1. [...] As many SSH destinations/LIST commands as wanted and needed.
    ///
    /// ### SSH destination
    /// Taken from the ssh(1) manpage:
    /// ssh connects and logs into the specified destination, which may be
    /// specified as either \[user@]hostname or a URI of the form
    /// ssh://\[user@]hostname\[:port].
    ///
    /// ### LIST command
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
    /// ## Extended
    /// The _extended_ config style is also line based, with the following properties:
    ///
    /// 1. Session name
    /// 1. Extra tmux command line options, most commonly **NONE**. _(currently options are unsupported in the rust tm version)_
    /// 1. Any tmux(1) command with whatever option tmux supports.
    /// 1. [...] As many tmux(1) commands as wanted and needed
    ///
    /// ### Replacement tags
    /// While parsing the commands, the following tags get replaced:
    ///
    /// | TAG     | Replacement
    /// |---------|------------
    /// | SESSION | Session name (first line value)
    /// | TMWIN   | Current window (starts with whatever tmux option base-index has, increases on every new-window found)
    /// | $HOME   | User home directory
    /// | ${HOME} | Same as $HOME
    ///
    /// # Examples
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
    /// ```text
    /// anotherexample
    /// NONE
    /// ganneff@host3
    /// LIST cat foo.list
    /// ```
    ///
    /// The following will open a tmux session `logmon`, with a window
    /// split in 3 panes, one tail-ing the messages log, another
    /// showing current date/time and a third showing htop. It will
    /// forbid tmux to rename the window.
    /// ```text
    /// nagioscfg
    /// NONE
    /// new-session -d -s SESSION -n SESSION ssh -t localhost 'TERM=xterm tail -f /var/log/messages'
    /// split-window -h -p 50 -d -t SESSION:TMWIN ssh -t localhost  'watch -n1 -d date -u'
    /// split-window -v -p 70 -d -t SESSION:TMWIN ssh -t localhost  'TERM=xterm htop'
    /// set-window-option -t SESSION:TMWIN automatic-rename off
    /// set-window-option -t SESSION:TMWIN allow-rename off
    /// ```
    fn read_session_file_and_attach(&mut self) -> Result<()> {
        trace!("Entering read_session_file");
        // Get the path of the session file
        let sesfile = self.sesfile.clone();
        let sesfilepath = sesfile.parent().ok_or_else(|| {
            anyhow!(
                "Could not determine directory for {}",
                self.sesfile.display()
            )
        })?;
        // Check if the file exists
        if !self.sesfile.exists() {
            return Err(anyhow!("Session file {} not found", self.sesfile.display()));
        }

        match self.sesfile.extension().and_then(OsStr::to_str) {
            None => self.sestype = SessionType::Simple,
            Some(v) => match v {
                "cfg" => self.sestype = SessionType::Extended,
                &_ => return Err(anyhow!("Unknown file extension {v}")),
            },
        }

        // Want to read the session config file
        let sesreader = BufReader::new(File::open(&self.sesfile)?);
        // Need session name later
        let mut sesname: String;

        let mut tmwin = *TMWIN;

        for (index, line) in sesreader.lines().enumerate() {
            trace!("Read line {}: {:?}", index + 1, line);
            // Replace token, if exists
            let line = tmreplace(&line?, &self.replace)?;
            debug!("Processing line {}: '{}'", index + 1, line);
            // Action to come depends on line we read and SessionType
            match index {
                0 => {
                    // First line is session name
                    debug!("Possible session name: {}", &line);
                    // Before we get to this place, we already tried
                    // looking for a session with the name the user gave
                    // us as argument. And it did not exist.
                    //
                    // Unlucky us, this first line may NOT be the same as
                    // that session name. So we check again, and if a
                    // session name like this already exists, we error
                    // out. Could, *maybe* attach to that? Unsure. Might
                    // be surprising.
                    sesname = self.set_name(&line)?.to_string();
                    if self.exists() {
                        info!("Session matches existing one, attaching");
                        self.attach()?;
                        return Ok(());
                    } else {
                        debug!("Calculated session name: {}", sesname);
                    }
                }
                1 => trace!("Ignoring 2nd line"),
                _ => {
                    debug!("Content line");
                    // Third and following lines are "content", so for
                    // simple configs either hostnames or LIST
                    // commands, for extended ones they are commands.
                    match &self.sestype {
                        SessionType::Simple => {
                            self.targets
                                .append(&mut parse_line(&line, &self.replace, sesfilepath)?)
                        }
                        SessionType::Extended => {
                            if line.contains("new-window") {
                                tmwin += 1;
                            }
                            let modline = line
                                .replace("SESSION", &self.sesname)
                                .replace("$HOME", "~/")
                                .replace("${HOME}", "~/")
                                .replace("TMWIN", &tmwin.to_string())
                                .expand_home()?
                                .into_os_string()
                                .into_string()
                                .expect("String convert failed");
                            self.targets.push(modline);
                        }
                    }
                }
            }
        }
        trace!("Finished parsing session file");
        debug!("Targets: {:#?}", self.targets);
        // Depending on session type, different action will happen
        match &self.sestype {
            SessionType::Simple => {
                // We have a nice set of hosts and a session name, lets set it all up
                self.synced = true;
                self.setup_simple_session()?;
                self.attach()?;
            }
            SessionType::Extended => {
                self.setup_extended_session()?;
                self.attach()?;
            }
        }
        Ok(())
    }

    /// Create a tmux session from an "extended" config.
    ///
    /// This just goes over all entries in [Session::targets] and executes
    /// them using tmux run-shell ability. Whatever the user setup in
    /// .cfg is executed - provided that tmux(1) knows it, ie. it is a
    /// valid tmux command.
    fn setup_extended_session(&mut self) -> Result<bool> {
        trace!("Entering setup_extended_session");
        debug!("Creating session {}", self.sesname);

        if self.targets.is_empty() {
            return Err(anyhow!("No targets setup, can not open session"));
        }

        for mut x in self.targets.clone() {
            debug!("Command: {}", x);
            x.insert_str(0, "tmux ");
            trace!("Actually running: {}", x);
            let output = TmuxCommand::new().run_shell().shell_command(&x).output()?;
            trace!("Shell: {:?}", output);
        }
        Ok(true)
    }

    /// Create a simple tmux session, that is, a session with one or
    /// multiple windows or panes opening SSH connections to a set of
    /// targets.
    ///
    /// Depending on value of session field [Session::synced] it will
    /// setup multiple windows, or one window with multiple panes.
    fn setup_simple_session(&mut self) -> Result<bool> {
        trace!("Entering setup_simple_session");
        debug!("Creating session {}", self.sesname);

        if self.targets.is_empty() {
            return Err(anyhow!("No targets setup, can not open session"));
        }
        TmuxCommand::new()
            .new_session()
            .detached()
            .session_name(&self.sesname)
            .window_name(&self.targets[0])
            .shell_command(format!("{} {}", *TMSSHCMD, &self.targets[0]))
            .output()?;

        // Which window are we at? Start with TMWIN, later on count up (if
        // we open more than one)
        let mut wincount = *TMWIN;
        self.setwinopt(wincount, "automatic-rename", "off")?;
        self.setwinopt(wincount, "allow-rename", "off")?;

        // Next check if there was more than one host, if so, open windows/panes
        // for them too.
        if self.targets.len() >= 2 {
            debug!("Got more than 1 target");
            let mut others = self.targets.clone().into_iter();
            // Skip the first, we already opened a connection
            others.next();
            for x in others {
                // For the syncssh session, we count how often we tried to create a pane
                let mut count = 1;
                loop {
                    debug!(
                        "Opening window/pane for {}, destination {}",
                        self.sesname, x
                    );
                    match self.synced {
                        true => {
                            // split pane
                            let output = TmuxCommand::new()
                                .split_window()
                                .size(&tmux_interface::commands::PaneSize::Percentage(1))
                                .detached()
                                .target_window(&self.sesname)
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
                                    return Err(anyhow!("Could not successfully create another pane for {}, tried {} times", x, count));
                                }
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
                            // And one more round
                            continue;
                        }
                        false => {
                            // For the plain ssh session, we count the window we are in
                            wincount += 1;
                            // new window
                            TmuxCommand::new()
                                .new_window()
                                .detached()
                                .add()
                                .window_name(&x)
                                .target_window(&self.sesname)
                                .shell_command(format!("{} {}", *TMSSHCMD, &x))
                                .output()?;
                            debug!("Window/Pane {} opened", wincount);
                            self.setwinopt(wincount, "automatic-rename", "off")?;
                            self.setwinopt(wincount, "allow-rename", "off")?;
                            break;
                        }
                    }
                }
            }
            match self.synced {
                true => {
                    // Now synchronize their input
                    self.setwinopt(wincount, "synchronize-pane", "on")?;
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
                        trace!("synced setup successful");
                        return Ok(true);
                    } else {
                        trace!("synced setup failed");
                        return Err(anyhow!("Setting layout failed"));
                    }
                }
                false => {
                    return Ok(true);
                }
            }
        }
        Ok(true)
    }

    /// Set an option for a tmux window
    ///
    /// tmux windows can have a large set of options attached. We do
    /// regularly want to set some.
    ///
    /// # Example
    /// ```
    /// # fn main() {
    /// session.setwinopt(windowindex, "automatic-rename", "off");
    /// # }
    /// ```
    fn setwinopt(&mut self, index: u32, option: &str, value: &str) -> Result<bool> {
        trace!("setwinopt");
        let target = format!("{}:{}", self.sesname, index);
        debug!("Setting Window ({}) option {} to {}", target, option, value);
        match TmuxCommand::new()
            .set_option()
            .window()
            .target(&target)
            .option(option)
            .value(value)
            .output()
        {
            Ok(_) => {
                debug!("Window option successfully set");
                Ok(true)
            }
            Err(error) => {
                return Err(anyhow!(
                    "Could not set window option {}: {:#?}",
                    option,
                    error
                ))
            }
        }
    }

    /// Break a session with many panes in one window into one with
    /// many windows.
    fn break_panes(&mut self) -> Result<bool> {
        // List of panes
        let panes: Vec<(String, String)> = String::from_utf8(
            TmuxCommand::new()
                .list_panes()
                .format("#{s/ssh //:pane_start_command} #{pane_id}")
                .session()
                .target(&self.sesname)
                .output()?
                .stdout(),
        )?
        .split_terminator('\n')
        .map(|s| s.to_string())
        .map(|x| {
            x.split_whitespace()
                .map(|y| y.trim().to_string())
                .collect_tuple::<(String, String)>()
                .unwrap()
        })
        .collect();
        trace!("{:#?}", panes);

        // Go over all panes, break them out into new windows. Window
        // name is whatever they had, minus a (possible) ssh in front
        for (pname, pid) in panes {
            trace!("Breaking off pane {pname}, id {pid}");
            TmuxCommand::new()
                .break_pane()
                .detached()
                .window_name(&pname)
                .src_pane(&pid)
                .output()?;
        }

        Ok(true)
    }

    /// Join many windows into one window with many panes
    fn join_windows(&mut self) -> Result<bool> {
        let windowlist: Vec<String> = String::from_utf8(
            TmuxCommand::new()
                .list_windows()
                .format("#{window_id}")
                .target_session(&self.sesname)
                .output()?
                .stdout(),
        )?
        .split_terminator('\n')
        .map(|s| s.to_string())
        .collect();
        debug!("Window IDs: {:#?}", windowlist);
        let first = windowlist.clone().into_iter().next().unwrap();
        debug!("First: {first:#?}");
        for id in windowlist {
            if id != first {
                let mut count = 1;
                loop {
                    trace!("Joining {} to {}", &id, &first);
                    let output = TmuxCommand::new()
                        .join_pane()
                        .detached()
                        .src_pane(&id)
                        .dst_pane(format!("{}:{}", self.sesname, first))
                        .output()?;
                    trace!("Output: {:?}", output);
                    if output.0.status.success() {
                        // Exit the loop, we made it and got the window joined as a pane
                        debug!("Window {} joined successfully", &id);
                        break;
                    } else {
                        // Didn't work, lets help tmux along and then retry this
                        debug!("join-pane did not work");
                        if count >= 3 {
                            return Err(anyhow!(
                                "Could not successfully join window {} into {}, tried {} times",
                                id,
                                first,
                                count
                            ));
                        }
                        count += 1;

                        let reason: String = String::from_utf8(output.0.stderr)
                            .expect("Could not parse tmux fail reason");

                        debug!("Failure reason: {}", reason.trim());
                        if reason
                            .trim()
                            .eq_ignore_ascii_case("create pane failed: pane too small")
                        {
                            debug!("Panes getting too small, need to adjust layout");
                            // No space for new pane -> redo the layout so windows are equally sized again
                            let out = TmuxCommand::new()
                                .select_layout()
                                .target_pane(&first)
                                .layout_name("main-horizontal")
                                .output()
                                .expect("Could not spread out layout");
                            trace!("Layout result: {:?}", out);
                        };
                    };
                    // And one more round
                    continue;
                }
            }
        }
        if TmuxCommand::new()
            .select_layout()
            .layout_name("tiled")
            .output()
            .unwrap()
            .0
            .status
            .success()
        {
            trace!("joining windows successful");
            self.setwinopt(*TMWIN, "synchronize-pane", "on")?;
            Ok(true)
        } else {
            trace!("joining windows failed");
            return Err(anyhow!("Setting layout failed"));
        }
    }
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
    static ref TMWIN: u32 = match TmuxCommand::new()
        .show_options()
        .global()
        .quiet()
        .value()
        .option("base-index")
        .output()
    {
        Ok(v) => v.to_string().trim().parse().unwrap_or(1),
        Err(_) => fromenvstatic!(asU32 "TMWIN", 1),
    };
}

/// Run ls
///
/// Simply runs `tmux list-sessions`
fn ls<W: Write>(handle: &mut BufWriter<W>) -> Result<()> {
    trace!("Entering ls");
    let sessions = TmuxCommand::new()
        .list_sessions()
        .output()
        .unwrap()
        .to_string();
    writeln!(handle, "{sessions}")?;
    trace!("Leaving ls");
    Ok(())
}

/// Tiny helper to replace the magic ++TMREPLACETM++
#[doc(hidden)]
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
fn parse_line(line: &str, replace: &Option<String>, current_dir: &Path) -> Result<Vec<String>> {
    trace!("Entered parse_line");
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
            let cmd: String = cmdparser
                .next()
                .ok_or_else(|| anyhow!("Empty LIST found - no command given"))?
                .replace("$HOME", "~/")
                .replace("${HOME}", "~/")
                .expand_home()?
                .into_os_string()
                .into_string()
                .expect("String convert failed");
            // Next we want the arguments.
            // Also, ~ and $HOME/${HOME} expansion are supported.
            let args: Vec<String> = cmdparser
                .map(|l| l.replace("$HOME", "~/").replace("${HOME}", "~/"))
                .map(|l| {
                    l.expand_home()
                        .expect("Could not successfully expand ~ for arguments of LIST call")
                        .into_os_string()
                        .into_string()
                        .expect("String convert failed")
                })
                .collect();
            debug!("cmd is {}", cmd);
            debug!("args are {:?}", args);

            // Our process spawner, pleased to hand us results as a nice
            // string seperated by newline (well, if output contains newlines)
            let cmdout = String::from_utf8(
                Command::new(&cmd)
                    .current_dir(&current_dir)
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

// Can't sensibly test main()
#[cfg(not(tarpaulin_include))]
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
    } else if cli.session.is_some() {
        let sespath = Path::join(Path::new(&*TMDIR), Path::new(&cli.session.clone().unwrap()));
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
                    TmuxCommand::new()
                        .new_session()
                        .session_name(&session.sesname)
                        .output()?;
                }
                Err(val) => error!("Error: {val}"),
            }
        };
    } else if cli.sshhosts != None || cli.multihosts != None {
        trace!("Session connecting somewhere");
        if session.exists() {
            session.attach()?;
        } else {
            if cli.sshhosts != None {
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
    use super::*;
    use regex::Regex;

    #[test]
    #[allow(clippy::bool_assert_comparison)]
    fn test_cmdline_getopts_simpleopt() {
        let mut session = Session {
            ..Default::default()
        };

        // Just a session
        let mut cli = Cli::parse_from("tm foo".split_whitespace());
        assert_eq!(
            cli.find_session_name(&mut session).unwrap(),
            "foo".to_string()
        );

        // -l is ls
        cli = Cli::parse_from("tm -l".split_whitespace());
        assert_eq!(cli.ls, true);

        // -k to kill a session
        cli = Cli::parse_from("tm -k killsession".split_whitespace());
        assert_eq!(cli.kill, Some("killsession".to_string()));
        assert_eq!(
            cli.find_session_name(&mut session).unwrap(),
            "killsession".to_string()
        );

        // -k to kill a session - second value on commandline should not
        // adjust session name.
        cli = Cli::parse_from("tm -k session ses2".split_whitespace());
        assert_eq!(cli.session, Some("ses2".to_string()));
        assert_eq!(
            cli.find_session_name(&mut session).unwrap(),
            "session".to_string()
        );

        // -v/-q goes via clap_verbosity, just check that we did not suddenly redefine it
        assert_eq!(cli.verbose.log_level_filter(), log::LevelFilter::Error);
        assert_eq!(cli.verbose.is_silent(), false);
        cli = Cli::parse_from("tm -v".split_whitespace());
        assert_eq!(cli.verbose.log_level_filter(), log::LevelFilter::Warn);
        assert_eq!(cli.verbose.is_silent(), false);
        cli = Cli::parse_from("tm -vvvv".split_whitespace());
        assert_eq!(cli.verbose.log_level_filter(), log::LevelFilter::Trace);
        cli = Cli::parse_from("tm -q".split_whitespace());
        assert_eq!(cli.verbose.log_level_filter(), log::LevelFilter::Off);
        assert_eq!(cli.verbose.is_silent(), true);

        // -n wants a second session to same hosts as existing one
        let mut cli = Cli::parse_from("tm -n".split_whitespace());
        assert_eq!(cli.second, true);

        // -g attaches existing session, but different window config
        cli = Cli::parse_from("tm -g".split_whitespace());
        assert_eq!(cli.group, true);
    }

    #[test]
    #[allow(clippy::bool_assert_comparison)]
    fn test_cmdline_getopts_s() {
        let mut session = Session {
            ..Default::default()
        };
        // -s is ssh to one or more hosts
        let mut cli = Cli::parse_from("tm -s testhost".split_whitespace());
        assert_eq!(cli.sshhosts, Some(vec!["testhost".to_string()]));
        assert_eq!(
            cli.find_session_name(&mut session).unwrap(),
            "s_testhost".to_string()
        );
        cli = Cli::parse_from("tm -s testhost morehost andonemore".split_whitespace());
        assert_eq!(
            cli.sshhosts,
            Some(vec![
                "testhost".to_string(),
                "morehost".to_string(),
                "andonemore".to_string()
            ])
        );
        assert_eq!(
            cli.find_session_name(&mut session).unwrap(),
            "s_andonemore_morehost_testhost".to_string()
        );

        // Combine with -n
        cli = Cli::parse_from("tm -n -s testhost".split_whitespace());
        let sesname = cli.find_session_name(&mut session).unwrap();
        // -n puts a random number into the name, so check with regex
        let re = Regex::new(r"^s_\d+_testhost$").unwrap();
        assert_eq!(re.is_match(&sesname), true);
        assert_ne!(
            cli.find_session_name(&mut session).unwrap(),
            "s_testhost".to_string()
        );
    }

    #[test]
    #[allow(clippy::bool_assert_comparison)]
    fn test_cmdline_getopts_ms() {
        let mut session = Session {
            ..Default::default()
        };

        // -m is ssh to one or more hosts, synchronized input
        let mut cli = Cli::parse_from("tm -m testhost".split_whitespace());
        assert_eq!(cli.multihosts, Some(vec!["testhost".to_string()]));
        cli = Cli::parse_from("tm -m testhost morehost andonemore".split_whitespace());
        assert_eq!(
            cli.multihosts,
            Some(vec![
                "testhost".to_string(),
                "morehost".to_string(),
                "andonemore".to_string()
            ])
        );
        assert_eq!(
            cli.find_session_name(&mut session).unwrap(),
            "ms_andonemore_morehost_testhost".to_string()
        );

        // Combine with -n
        cli = Cli::parse_from("tm -n ms testhost morehost".split_whitespace());
        let sesname = cli.find_session_name(&mut session).unwrap();
        // -n puts a random number into the name, so check with regex
        let re = Regex::new(r"^ms_\d+_morehost_testhost$").unwrap();
        assert_eq!(re.is_match(&sesname), true);
        assert_ne!(
            cli.find_session_name(&mut session).unwrap(),
            "ms_morehost_testhosts".to_string()
        );
    }

    #[test]
    #[allow(clippy::bool_assert_comparison)]
    fn test_cmdline_ls() {
        let mut cli = Cli::parse_from("tm ls".split_whitespace());
        assert_eq!(cli.ls, false);
        assert_eq!(cli.command, Some(Commands::Ls {}));

        // -v/-q goes via clap_verbosity, just check that we did not suddenly redefine it
        assert_eq!(cli.verbose.log_level_filter(), log::LevelFilter::Error);
        assert_eq!(cli.verbose.is_silent(), false);
        cli = Cli::parse_from("tm -v".split_whitespace());
        assert_eq!(cli.verbose.log_level_filter(), log::LevelFilter::Warn);
        assert_eq!(cli.verbose.is_silent(), false);
    }

    #[test]
    #[allow(clippy::bool_assert_comparison)]
    fn test_cmdline_s() {
        let mut session = Session {
            ..Default::default()
        };
        // s is ssh to one or more hosts
        let mut cli = Cli::parse_from("tm s testhost".split_whitespace());
        let mut cc = cli.command.as_ref().unwrap();
        let mut val = vec!["testhost".to_string()];
        assert_eq!(cc, &Commands::S { hosts: val });
        assert_eq!(
            cli.find_session_name(&mut session).unwrap(),
            "s_testhost".to_string()
        );
        cli = Cli::parse_from("tm s testhost morehost andonemore".split_whitespace());
        cc = cli.command.as_ref().unwrap();
        val = vec![
            "testhost".to_string(),
            "morehost".to_string(),
            "andonemore".to_string(),
        ];
        assert_eq!(cc, &Commands::S { hosts: val });
        assert_eq!(
            cli.find_session_name(&mut session).unwrap(),
            "s_andonemore_morehost_testhost".to_string()
        );
    }

    #[test]
    #[allow(clippy::bool_assert_comparison)]
    fn test_cmdline_k() {
        let mut session = Session {
            ..Default::default()
        };
        // k is kill that session
        let cli = Cli::parse_from("tm k session".split_whitespace());
        assert_eq!(
            cli.find_session_name(&mut session).unwrap(),
            "session".to_string()
        );
        let cc = cli.command.as_ref().unwrap();
        assert_eq!(
            cc,
            &Commands::K {
                sesname: "session".to_string()
            }
        );
        assert_eq!(
            cli.find_session_name(&mut session).unwrap(),
            "session".to_string()
        );
    }

    #[test]
    fn test_set_name() {
        let mut session = Session {
            ..Default::default()
        };

        assert_eq!("test", session.set_name("test").unwrap());
        assert_eq!("test_second", session.set_name("test second").unwrap());
        assert_eq!("test_third", session.set_name("test:third").unwrap());
        assert_eq!(
            "test_fourth_fifth",
            session.set_name("test fourth fifth").unwrap()
        );
        assert_eq!(
            "test_fourth_fifth_more_words_here_set_in",
            session
                .set_name("test fourth_fifth:more words here\"set in")
                .unwrap()
        );
    }

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
        env::set_var("TNWIN", "1");
        assert_eq!(*TMPDIR, "/tmp");
        assert_eq!(*TMOPTS, "-2");
        assert_eq!(*TMSORT, true);
        assert_eq!(*TMSESSHOST, false);
        assert_eq!(*TMSSHCMD, "ssh");
        assert_eq!(*TMWIN, 1);
    }

    #[test]
    fn test_kill_ls_and_exists() {
        let mut session = Session {
            ..Default::default()
        };
        session.set_name("tmtestsession").unwrap();
        assert_eq!(false, session.exists());
        TmuxCommand::new()
            .new_session()
            .session_name(&session.sesname)
            .detached()
            .shell_command("/bin/bash")
            .output()
            .unwrap();
        assert_eq!(true, session.exists());

        // We want to check the output of ls contains our session from
        // above, so have it "write" it to a variable, then check if
        // the variable contains the session name.
        let lstext = Vec::new();
        let mut handle = BufWriter::new(lstext);
        ls(&mut handle).unwrap();
        handle.flush().unwrap();

        assert_eq!(true, session.kill().unwrap());
        assert!(session.kill().is_err());
        assert_eq!(false, session.exists());

        // And now check what got "written" into the variable
        let (recovered_writer, _buffered_data) = handle.into_parts();
        let output = String::from_utf8(recovered_writer).unwrap();
        assert_eq!(output.contains(&session.sesname), true);
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
        let mut res = parse_line(&line, &replace, &current_dir).unwrap();
        assert_eq!(res, vec!["justonehost".to_string()]);
        line = "LIST /bin/echo \"onehost\ntwohost\nthreehost\"";
        replace = None;
        current_dir = Path::new("/");
        res = parse_line(&line, &replace, &current_dir).unwrap();
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
        res = parse_line(&line, &replace, &current_dir).unwrap();
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
        res = parse_line(&line, &replace, &current_dir).unwrap();
        let empty: Vec<String> = vec![];
        assert_eq!(res, empty);
    }
}
