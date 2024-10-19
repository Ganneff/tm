//! tm - a tmux helper
//!
//! SPDX-License-Identifier: BSD-2-Clause
//!
//! Copyright (C) 2011-2024 Joerg Jaspert <joerg@debian.org>
//!

#![warn(missing_docs)]

use crate::{parse_line, tmreplace, TMSSHCMD, TMWIN};
use anyhow::{anyhow, Result};
use itertools::Itertools;
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use std::{
    ffi::OsStr,
    fs::File,
    io::{BufRead, BufReader},
    path::PathBuf,
    process::Stdio,
};
use tmux_interface::{
    AttachSession, BreakPane, HasSession, JoinPane, KillSession, ListPanes, ListWindows,
    NewSession, NewWindow, RunShell, SelectLayout, SetOption, SplitWindow, Tmux,
};
use tracing::{debug, info, trace};

#[derive(Default, Debug)]
#[non_exhaustive]
/// Possible Session types
pub enum SessionType {
    #[default]
    /// Simple - 2 initial lines, followed by 1 to many SSH destinations
    Simple,
    /// Extended - 2 initial lines, followed by 1 to many tmux commands
    Extended,
}

#[derive(Debug, Default)]
#[non_exhaustive]
/// Store session related information
pub struct Session {
    /// The session name
    pub name: String,
    /// Should this be "grouped" - shares the same set of windows, new
    /// windows are linked to all sessions in the group, any window
    /// closed is removed from all sessions. But sessions are
    /// separate, as are their current/previous window and session
    /// options.
    pub grouped: bool,
    /// The session name when grouped
    pub gsesname: String,
    /// The path to a session file
    pub sesfile: PathBuf,
    /// Type of session (file), from extension of file
    pub sestype: SessionType,
    /// Synchronized session? (Synchronized - input goes to all visible panes in tmux at once)
    pub synced: bool,
    /// List of SSH Destinations / commands for the session
    pub targets: Vec<String>,
    /// Token for the string replacement in session files
    pub replace: Option<String>,
}

impl Session {
    /// Takes a string, applies some cleanup, then stores it as
    /// session name
    #[tracing::instrument(level = "trace")]
    pub fn set_name<S>(&mut self, newname: S)
    where
        S: AsRef<str> + std::fmt::Display + std::fmt::Debug,
    {
        let newname = newname.as_ref();
        // Replace a set of characters we do not want in the session name with _
        self.name = newname.replace(&[' ', ':', '"', '.'][..], "_");
        debug!("Session name now: {}", self.name);
    }

    /// Kill session
    #[tracing::instrument(level = "trace", ret, err)]
    pub fn realkill<S>(&self, tokill: S) -> Result<bool>
    where
        S: AsRef<str> + std::fmt::Display + std::fmt::Debug,
    {
        let tokill = tokill.as_ref();
        if Tmux::with_command(HasSession::new().target_session(tokill))
            .into_command()
            .stderr(Stdio::null())
            .status()?
            .success()
        {
            debug!("Asked to kill session {}", tokill);
            if Tmux::with_command(KillSession::new().target_session(tokill))
                .status()?
                .success()
            {
                info!("Session {} is no more", tokill);
                Ok(true)
            } else {
                info!("Session {} could not be killed!", tokill);
                Err(anyhow!("Session {} could not be killed!", tokill))
            }
        } else {
            debug!("No such session {}", tokill);
            Err(anyhow!("No such session {}", tokill))
        }
    }

    /// Kill current known session
    #[tracing::instrument(level = "trace", ret, err)]
    pub fn kill(&self) -> Result<bool> {
        self.realkill(&self.name)
    }

    /// Check if a session exists
    #[tracing::instrument(level = "trace", ret)]
    pub fn exists(&self) -> bool {
        Tmux::with_command(HasSession::new().target_session(&self.name))
            .into_command()
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success()
    }

    /// Attach to a running (or just prepared) tmux session
    #[tracing::instrument(level = "trace", ret, err, skip(self), fields(self.sesname))]
    pub fn attach(&mut self) -> Result<bool> {
        let ret = if self.exists() {
            if self.grouped {
                let mut rng = rand::thread_rng();
                let insert: u16 = rng.gen();
                self.gsesname = format!("{}_{}", insert, self.name);
                debug!(
                    "Grouped session wanted, setting new session {}, linking it with {}",
                    self.gsesname, self.name
                );
                if cfg!(test) {
                    Tmux::with_command(
                        NewSession::new()
                            .detached()
                            .session_name(&self.gsesname)
                            .group_name(&self.name),
                    )
                    .status()?;
                } else {
                    Tmux::with_command(
                        NewSession::new()
                            .session_name(&self.gsesname)
                            .group_name(&self.name),
                    )
                    .status()?;
                }
                info!(
                    "Removing grouped session {} (not the original!)",
                    &self.gsesname
                );
                if cfg!(test) {
                    println!("Not removing grouped session {}", self.gsesname);
                } else {
                    self.realkill(&self.gsesname)?;
                }
                true
            } else if cfg!(test) {
                println!("Can not attach in test mode");
                match self.name.as_str() {
                    "fakeattach" => true,
                    &_ => false,
                }
            } else {
                Tmux::with_command(AttachSession::new().target_session(&self.name))
                    .status()?
                    .success()
            }
        } else {
            false
        };
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
    #[tracing::instrument(level = "trace", ret, err)]
    pub fn read_session_file_and_attach(&mut self) -> Result<()> {
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
                    // Unlucky us, this first line may NOT be the same
                    // as that session name. So we check again, and if
                    // a session name like this already exists, we try
                    // attaching to it.
                    self.set_name(line);
                    if self.exists() {
                        info!("Session matches existing one, attaching");
                        self.attach()?;
                        return Ok(());
                    } else {
                        debug!("Calculated session name: {}", self.name);
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
                            let modline = shellexpand::full(
                                &line
                                    .replace("SESSION", &self.name)
                                    .replace("$HOME", "~/")
                                    .replace("${HOME}", "~/")
                                    .replace("TMWIN", &tmwin.to_string()),
                            )?
                            .to_string();
                            // .expand_home()?
                            // .into_os_string()
                            // .into_string()
                            // .expect("String convert failed");
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
            }
            SessionType::Extended => {
                self.setup_extended_session()?;
            }
        }
        self.attach()?;
        Ok(())
    }

    /// Create a tmux session from an "extended" config.
    ///
    /// This just goes over all entries in [Session::targets] and executes
    /// them using tmux run-shell ability. Whatever the user setup in
    /// .cfg is executed - provided that tmux(1) knows it, ie. it is a
    /// valid tmux command.
    #[tracing::instrument(level = "trace", ret, err)]
    pub fn setup_extended_session(&mut self) -> Result<bool> {
        if self.targets.is_empty() {
            return Err(anyhow!("No targets setup, can not open session"));
        }

        for mut command in self.targets.clone() {
            debug!("Command: {}", command);
            // The trick with run-shell later is nice, but if we
            // happen to be the very first tmux session to start, it
            // will break with "No tmux server running". So whenever
            // we see a "new-session" command, we setup a fake session
            // which closes itself after one second, just so that one
            // is there and makes run-shell work.
            //
            // Alternative would be parsing the new-session line to
            // correctly run new-session ourself, but I do not want
            // to parse.
            //
            // FIXME: We should check if a tmux is running and only
            // then do the trick.
            let first = command.split_whitespace().next();
            match first {
                Some("new-session") => {
                    debug!("New Session");
                    let tempsesname: String = thread_rng()
                        .sample_iter(&Alphanumeric)
                        .take(30)
                        .map(char::from)
                        .collect();
                    Tmux::with_command(
                        NewSession::new()
                            .detached()
                            .session_name(&tempsesname)
                            .window_name("to be killed")
                            .shell_command("sleep 1"),
                    )
                    .status()?;
                }
                Some(&_) => {
                    debug!("Whatever else");
                }
                None => {}
            }
            command.insert_str(0, "tmux ");
            trace!("Actually running: {}", command);
            let output = Tmux::with_command(RunShell::new().shell_command(command)).output()?;
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
    #[tracing::instrument(level = "trace", ret, err, skip(self), fields(self.sesname, self.targets))]
    pub fn setup_simple_session(&mut self) -> Result<bool> {
        if self.targets.is_empty() {
            return Err(anyhow!("No targets setup, can not open session"));
        }

        // And start the session by opening it with the shell command
        // directly going to the first target
        Tmux::with_command(
            NewSession::new()
                .detached()
                .session_name(&self.name)
                .window_name(&self.targets[0])
                .shell_command(format!("{} {}", *TMSSHCMD, &self.targets[0])),
        )
        .status()?;
        trace!("Session started");

        // Which window are we at? Start with TMWIN, later on count up (if
        // we open more than one)
        let mut wincount = *TMWIN;
        self.setwinopt(wincount, "automatic-rename", "off")?;
        self.setwinopt(wincount, "allow-rename", "off")?;

        // Next check if there was more than one host, if so, open windows/panes
        // for them too.
        debug!(?self.targets);
        if self.targets.len() >= 2 {
            debug!("Got more than 1 target");
            let mut others = self.targets.clone().into_iter();
            // Skip the first, we already opened a connection
            others.next();
            for target in others {
                // For the syncssh session, we count how often we tried to create a pane
                let mut count = 1;
                loop {
                    debug!(
                        "Opening window/pane for {}, destination {}",
                        self.name, target
                    );
                    match self.synced {
                        true => {
                            // split pane
                            let output = Tmux::with_command(
                                SplitWindow::new()
                                    .detached()
                                    .target_window(&self.name)
                                    .size(&tmux_interface::commands::PaneSize::Percentage(1))
                                    .target_pane(format!("{}:1", self.name))
                                    .shell_command(format!("{} {}", *TMSSHCMD, &target)),
                            )
                            .output()?;

                            trace!("New pane: {:?}", output);
                            if output.0.status.success() {
                                // Exit the loop, we made it and got the window
                                debug!("Pane opened successfully");
                                break;
                            } else {
                                // Didn't work, lets help tmux along and then retry this
                                debug!("split-window did not work");
                                if count >= 3 {
                                    return Err(anyhow!("Could not successfully create another pane for {}, tried {} times", target, count));
                                }
                                count += 1;

                                let reason: String = String::from_utf8(output.0.stderr)
                                    .expect("Could not parse tmux fail reason");

                                debug!("Failure reason: {}", reason.trim());
                                if reason.trim().eq_ignore_ascii_case("no space for new pane") {
                                    debug!("Panes getting too small, need to adjust layout");
                                    // No space for new pane -> redo the layout so windows are equally sized again
                                    let out = Tmux::with_command(
                                        SelectLayout::new()
                                            .target_pane(format!("{}:{}", self.name, wincount))
                                            .layout_name("main-horizontal"),
                                    )
                                    .output()?;
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
                            Tmux::with_command(
                                NewWindow::new()
                                    .detached()
                                    .after()
                                    .window_name(&target)
                                    .target_window(&self.name)
                                    .shell_command(format!("{} {}", *TMSSHCMD, &target)),
                            )
                            .status()?;
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
                    if Tmux::with_command(SelectLayout::new().layout_name("tiled"))
                        .status()?
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
    #[tracing::instrument(level = "trace", ret, err, skip(self))]
    pub fn setwinopt<S, T>(&mut self, index: u32, option: S, value: T) -> Result<bool>
    where
        S: AsRef<str> + std::fmt::Display + std::fmt::Debug,
        T: AsRef<str> + std::fmt::Display + std::fmt::Debug,
    {
        let option = option.as_ref();
        let value = value.as_ref();
        let target = format!("{}:{}", self.name, index);
        debug!("Setting Window ({}) option {} to {}", target, option, value);
        match Tmux::with_command(
            SetOption::new()
                .window()
                .target(&target)
                .option(option)
                .value(value),
        )
        .output()
        {
            Ok(_) => {
                debug!("Window option successfully set");
                Ok(true)
            }
            Err(error) => Err(anyhow!(
                "Could not set window option {}: {:#?}",
                option,
                error
            )),
        }
    }

    /// Break a session with many panes in one window into one with
    /// many windows.
    #[tracing::instrument(level = "trace", ret, err)]
    pub fn break_panes(&mut self) -> Result<bool> {
        // List of panes
        let panes: Vec<(String, String)> = String::from_utf8(
            Tmux::with_command(
                ListPanes::new()
                    .format("#{s/ssh //:pane_start_command} #{pane_id}")
                    .session()
                    .target(&self.name),
            )
            .output()?
            .stdout(),
        )?
        .split_terminator('\n')
        .map(|x| {
            x.split_whitespace()
                .map(|y| y.trim().to_string())
                .collect_tuple::<(String, String)>()
                .unwrap_or_else(|| panic!("Could not split pane information: {}", x))
        })
        .collect();
        trace!("{:#?}", panes);

        // Go over all panes, break them out into new windows. Window
        // name is whatever they had, minus a (possible) ssh in front
        for (pname, pid) in panes {
            trace!("Breaking off pane {pname}, id {pid}");
            Tmux::with_command(
                BreakPane::new()
                    .detached()
                    .window_name(&pname)
                    .src_pane(&pid)
                    .dst_window(self.name.to_string()),
            )
            .status()?;
        }

        Ok(true)
    }

    /// Join many windows into one window with many panes
    #[tracing::instrument(level = "trace", ret, err)]
    pub fn join_windows(&mut self) -> Result<bool> {
        let windowlist: Vec<String> = String::from_utf8(
            Tmux::with_command(
                ListWindows::new()
                    .format("#{window_id}")
                    .target_session(&self.name),
            )
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
                    let output = Tmux::with_command(
                        JoinPane::new()
                            .detached()
                            .src_pane(&id)
                            .dst_pane(format!("{}:{}", self.name, first)),
                    )
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
                            let out = Tmux::with_command(
                                SelectLayout::new()
                                    .target_pane(&first)
                                    .layout_name("main-horizontal"),
                            )
                            .output()?;
                            trace!("Layout result: {:?}", out);
                        };
                    };
                    // And one more round
                    continue;
                }
            }
        }
        self.setwinopt(*TMWIN, "synchronize-pane", "on")?;
        if Tmux::with_command(SelectLayout::new().target_pane(&first).layout_name("tiled"))
            .status()?
            .success()
        {
            trace!("joining windows successful");
            Ok(true)
        } else {
            trace!("joining windows in pane {} failed", &first);
            Err(anyhow!("Setting layout failed"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Session;
    use crate::TMWIN;

    #[test]
    fn test_set_name() {
        let mut session = Session {
            ..Default::default()
        };

        session.set_name("test");
        assert_eq!("test", session.name);
        session.set_name("test second");
        assert_eq!("test_second", session.name);
        session.set_name("test:third");
        assert_eq!("test_third", session.name);
        session.set_name("test_fourth_fifth_more_words_here\"set_in");
        assert_eq!("test_fourth_fifth_more_words_here_set_in", session.name);
    }
    #[test]
    fn test_setup_extended_session() {
        let mut session = Session {
            ..Default::default()
        };
        session.set_name("testextended");
        // Fail, we have no data in session.targets yet
        assert!(session.setup_extended_session().is_err());

        // Put two lines in
        session.targets.push(format!(
            "new-session -d -s {0} -n {0} /bin/bash",
            session.name
        ));
        session.targets.push(format!(
            "split-window -h -p 50 -d -t {}:{} /bin/bash -c 'watch -n1 -d date -u'",
            session.name, *TMWIN
        ));
        session.targets.push(format!(
            "new-window -d -t {}:{} /bin/bash -c 'watch -n1 -d date -u'",
            session.name, 3
        ));

        // This should work out
        session.setup_extended_session().unwrap();

        // // We want to check the output of ls contains our session from
        // // above, so have it "write" it to a variable, then check if
        // // the variable contains the session name and that it has two windows
        // let lstext = Vec::new();
        // let mut handle = BufWriter::new(lstext);
        // ls(&mut handle).unwrap();
        // handle.flush().unwrap();

        // // And now check what got "written" into the variable
        // let (recovered_writer, _buffered_data) = handle.into_parts();
        // let output = String::from_utf8(recovered_writer).unwrap();
        // let checktext = format!("{}: 2 windows", session.sesname);
        // assert!(
        //     output.contains(&checktext),
        //     "Could not correctly setup extended session, output is {:#?}",
        //     output
        // );

        // At the end, get rid of the test session
        assert!(session.kill().unwrap());
    }
}
