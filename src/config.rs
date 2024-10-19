//! tm - a tmux helper
//!
//! SPDX-License-Identifier: BSD-2-Clause
//!
//! Copyright (C) 2011-2024 Joerg Jaspert <joerg@debian.org>
//!

#![warn(missing_docs)]

use anyhow::anyhow;
use clap::{Parser, Subcommand};
use fehler::{throw, throws};
use rand::Rng;
use tracing::debug;

use crate::{TMSESSHOST, TMSORT};

use crate::Session;

#[derive(Debug, Parser)]
#[non_exhaustive]
#[clap(author, version, about)]
#[clap(propagate_version = true)]
#[clap(arg_required_else_help = true)]
#[clap(dont_collapse_args_in_usage = true)]
/// Options for tm, they are closely resembling (ought to be
/// compatible to) the ones from the old shell script.
pub struct Cli {
    /// subcommands
    #[clap(subcommand)]
    pub command: Option<Commands>,

    /// List running sessions
    ///
    /// This is basically `tmux ls`
    #[clap(short, display_order = 10)]
    pub ls: bool,

    /// Open SSH session to the destination
    ///
    /// The arguments are the destinations for `ssh(1)`, which may be
    /// specified as either \[user@]hostname or a URI of the form
    /// ssh://\[user@]hostname\[:port].
    ///
    /// When multiple destinations are specified, they are all opened
    /// into separate tmux windows (not sessions!).
    #[clap(short = 's', display_order = 15, num_args = 1..)]
    pub sshhosts: Option<Vec<String>>,

    /// Open multi SSH sessions to hosts, synchronizing input.
    ///
    /// The same details for the arguments as for [Cli::sshhosts] applies.
    ///
    /// When multiple destinations are specified, they are all opened
    /// into one single tmux window with many panes in there.
    /// Additionally, the "synchronize-input" option is turned on, so
    /// that anything entered will be send to every host.
    #[clap(short = 'm', display_order = 20, num_args = 1..)]
    pub multihosts: Option<Vec<String>>,

    /// Open as second session to the same set of hosts as an existing
    /// one, instead of attaching to the existing
    ///
    /// This way more than one session to the same set of ssh
    /// destinations can be opened and used.
    #[clap(short = 'n', display_order = 25)]
    pub second: bool,

    /// Group session - attach to an existing session, but keep
    /// separate window config
    ///
    /// This will show the same set of windows, but allow different
    /// handling of the session according to client. This way one
    /// client could display the first, another the second window.
    /// Without this option, a second client would always show the
    /// same content as the first.
    #[clap(short = 'g', display_order = 30)]
    pub group: bool,

    /// Kill a session, Session name as shown by ls
    #[clap(short = 'k', display_order = 35)]
    pub kill: Option<String>,

    /// Setup session according to config file in TMDIR
    #[clap(short = 'c', display_order = 40)]
    pub config: Option<String>,

    #[clap(flatten)]
    pub verbose: clap_verbosity_flag::Verbosity,

    /// Either plain tmux session name, or session/file found in TMDIR
    ///
    /// If this exists as a tmux session, it behaves like `tmux
    /// attach`. Otherwise it checks TMDIR for existence of a config
    /// file and will open a session as specified in there.
    #[clap(display_order = 50)]
    pub session: Option<String>,

    /// Value to use for replacing in session files (see their help)
    #[clap(display_order = 55)]
    pub replace: Option<String>,

    /// Break a multi-session pane into single windows
    #[clap(short = 'b', display_order = 60)]
    pub breakw: Option<String>,

    /// Join multiple windows into one single one with many panes
    #[clap(short = 'j', display_order = 65)]
    pub joinw: Option<String>,
}

#[derive(Subcommand, Debug, PartialEq)]
#[non_exhaustive]
/// Holds list of subcommands in use for tm
pub enum Commands {
    /// List running sessions
    ///
    /// This is basically `tmux ls`
    #[clap(display_order = 10)]
    Ls {},

    /// Open SSH session to the destination
    ///
    /// When multiple destinations are specified, they are all opened
    /// into separate tmux windows (not sessions!).
    #[clap(display_order = 15)]
    S {
        /// Target destinations for `ssh(1)`, which may be specified as
        /// either \[user@]hostname or a URI of the form
        /// ssh://\[user@]hostname\[:port].
        #[clap(required = true)]
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
        #[clap(required = true)]
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
    #[throws(anyhow::Error)]
    #[tracing::instrument(level = "trace", ret, err, skip(self), fields(name, second = self.second))]
    pub fn session_name_from_hosts(&self) -> String {
        let mut hosts = self.get_hosts()?;
        debug!(
            "Need to build session name from: {:?}, TMSESSHOST: {}",
            hosts, *TMSESSHOST
        );

        if *TMSORT {
            hosts.sort();
        }
        hosts.insert(0, self.get_insert()?);

        if self.second {
            let mut rng = rand::thread_rng();
            let insert: u16 = rng.gen();
            debug!(
                "Second session wanted, inserting {} into session name",
                insert
            );
            hosts.insert(1, insert.to_string());
        }
        let name = hosts.join("_");
        tracing::Span::current().record("name", &name);
        name
    }

    /// Find (and set) a session name. Appears we have many
    /// possibilities to get at one, depending how we are called.
    #[throws(anyhow::Error)]
    #[tracing::instrument(level = "trace", skip(self), ret, err, err)]
    pub fn find_session_name(&self, session: &mut Session) -> String {
        let possiblename: String = {
            if self.kill.is_some() {
                self.kill.clone().unwrap()
            } else if self.session.is_some() {
                self.session.clone().unwrap()
            } else if self.config.is_some() {
                self.config.clone().unwrap()
            } else if self.sshhosts.is_some() || self.multihosts.is_some() {
                self.session_name_from_hosts()?
            } else if self.breakw.is_some() {
                self.breakw.as_ref().unwrap().clone()
            } else if self.joinw.is_some() {
                self.joinw.as_ref().unwrap().clone()
            } else if self.command.is_some() {
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
        session.set_name(possiblename);
        session.name.to_string()
    }

    /// Returns a string depending on subcommand called, to adjust
    /// session name with.
    #[tracing::instrument(level = "trace", skip(self), ret)]
    #[throws(anyhow::Error)]
    pub fn get_insert(&self) -> String {
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
    #[throws(anyhow::Error)]
    #[tracing::instrument(level = "trace", skip(self), ret, err)]
    pub fn get_hosts(&self) -> Vec<String> {
        match &self.sshhosts {
            Some(v) => v.to_vec(),
            None => match &self.multihosts {
                Some(v) => v.to_vec(),
                None => match &self.command.as_ref().unwrap() {
                    Commands::S { hosts } | Commands::Ms { hosts } => hosts.clone(),
                    &_ => throw!(anyhow!("No hosts supplied, can not get any")),
                },
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Cli, Commands};
    use crate::session::Session;
    use clap::Parser;
    use regex::Regex;

    #[test]
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
        assert!(cli.ls);

        // -k to kill a session
        cli = Cli::parse_from("tm -k killsession".split_whitespace());
        assert_eq!(cli.kill, Some("killsession".to_string()));
        assert_eq!(
            cli.find_session_name(&mut session).unwrap(),
            "killsession".to_string()
        );

        // -b to break a session into many windows
        cli = Cli::parse_from("tm -b breaksession".split_whitespace());
        assert_eq!(cli.breakw, Some("breaksession".to_string()));
        assert_eq!(
            cli.find_session_name(&mut session).unwrap(),
            "breaksession".to_string()
        );

        // -j to join many windows into one pane
        cli = Cli::parse_from("tm -j joinsession".split_whitespace());
        assert_eq!(cli.joinw, Some("joinsession".to_string()));
        assert_eq!(
            cli.find_session_name(&mut session).unwrap(),
            "joinsession".to_string()
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
        assert!(!cli.verbose.is_silent());
        cli = Cli::parse_from("tm -v".split_whitespace());
        assert_eq!(cli.verbose.log_level_filter(), log::LevelFilter::Warn);
        assert!(!cli.verbose.is_silent());
        cli = Cli::parse_from("tm -vvvv".split_whitespace());
        assert_eq!(cli.verbose.log_level_filter(), log::LevelFilter::Trace);
        cli = Cli::parse_from("tm -q".split_whitespace());
        assert_eq!(cli.verbose.log_level_filter(), log::LevelFilter::Off);
        assert!(cli.verbose.is_silent());

        // -n wants a second session to same hosts as existing one
        let mut cli = Cli::parse_from("tm -n".split_whitespace());
        assert!(cli.second);

        // -g attaches existing session, but different window config
        cli = Cli::parse_from("tm -g".split_whitespace());
        assert!(cli.group);
    }
    #[test]
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
        assert!(re.is_match(&sesname));
        assert_ne!(
            cli.find_session_name(&mut session).unwrap(),
            "s_testhost".to_string()
        );
    }

    #[test]
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
        assert!(re.is_match(&sesname));
        assert_ne!(
            cli.find_session_name(&mut session).unwrap(),
            "ms_morehost_testhosts".to_string()
        );
    }

    #[test]
    #[allow(clippy::bool_assert_comparison)]
    fn test_cmdline_ls() {
        let mut cli = Cli::parse_from("tm ls".split_whitespace());
        assert!(!cli.ls);
        assert_eq!(cli.command, Some(Commands::Ls {}));

        // -v/-q goes via clap_verbosity, just check that we did not suddenly redefine it
        assert_eq!(cli.verbose.log_level_filter(), log::LevelFilter::Error);
        assert!(!cli.verbose.is_silent());
        cli = Cli::parse_from("tm -v".split_whitespace());
        assert_eq!(cli.verbose.log_level_filter(), log::LevelFilter::Warn);
        assert!(!cli.verbose.is_silent());
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
    fn test_cmdline_b() {
        let mut session = Session {
            ..Default::default()
        };
        // k is kill that session
        let cli = Cli::parse_from("tm b session".split_whitespace());
        assert_eq!(
            cli.find_session_name(&mut session).unwrap(),
            "session".to_string()
        );
        let cc = cli.command.as_ref().unwrap();
        assert_eq!(
            cc,
            &Commands::B {
                sesname: "session".to_string()
            }
        );
        assert_eq!(
            cli.find_session_name(&mut session).unwrap(),
            "session".to_string()
        );
    }

    #[test]
    fn test_cmdline_j() {
        let mut session = Session {
            ..Default::default()
        };
        // k is kill that session
        let cli = Cli::parse_from("tm j session".split_whitespace());
        assert_eq!(
            cli.find_session_name(&mut session).unwrap(),
            "session".to_string()
        );
        let cc = cli.command.as_ref().unwrap();
        assert_eq!(
            cc,
            &Commands::J {
                sesname: "session".to_string()
            }
        );
        assert_eq!(
            cli.find_session_name(&mut session).unwrap(),
            "session".to_string()
        );
    }
}
