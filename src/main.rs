use chrono::{NaiveDateTime, TimeDelta};
use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};
use lazy_static::lazy_static;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::panic;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::time::Duration;

use env_logger;
use log::{debug, error, info, trace, warn};

const MAX_PLAYERS: usize = 64;
const NAME_LIMIT: usize = 15;

// TODO: move to some clean regex handler struct
lazy_static! {
    static ref SERVER_JOIN_REGEX: Regex = Regex::new(
        r"^player has entered the game\. ClientID=(?P<client_id>\d+)\s+addr=<\{(?P<ip>\[[^\]]+\]|[^:]+):(?P<port>\d+)\}>\s+sixup=(?P<sixup>[01])$"
    ).unwrap();
    static ref GAME_LEAVE_REGEX: Regex = Regex::new(
        r"^leave player='(?P<cid>\d+):(?P<name>.*)'$"
    ).unwrap();
    static ref CHAT_MESSAGE_REGEX: Regex = Regex::new(
        r"^(?P<cid>\d+):(?P<unknown>[^:]+):(?P<name>[^:]+): (?P<message>.*)$"
    ).unwrap();
    static ref CHAT_FINISH_REGEX: Regex = Regex::new(
        r"^\*\*\*\s(?P<name>\S+)\sfinished in:\s(?P<minutes>\d+)\sminute\(s\)\s(?P<seconds>[\d.]+)\ssecond\(s\)$"
    ).unwrap();
    static ref DDNET_VERSION_REGEX: Regex = Regex::new(
        r"^cid=(?P<cid>\d+)\sversion=(?P<version>\d+)$"
    ).unwrap();
    static ref CHAT_JOIN_REGEX: Regex = Regex::new(
        r"^\*\*\*\s'(?P<name>[^']+)' entered and joined the game$"
    ).unwrap();
    static ref CHAT_RENAME_REGEX: Regex = Regex::new(
        r"^\*\*\*\s'(?P<old>[^']+)' changed name to '(?P<new>[^']+)'$"
    ).unwrap();
    static ref CHAT_TIMEOUT_REGEX: Regex = Regex::new(
        r"^\*\*\*\s'(?P<name>[^']+)' would have timed out, but can use timeout protection now$"
    ).unwrap();

    static ref ENGINE_SERVER_START_REGEX: Regex = Regex::new(
        r"^running on (?P<platform>\S+)$"
    ).unwrap();
    static ref SERVER_RCON_BAN_REGEX: Regex = Regex::new(
        r"^ClientID=(?P<cid>\d+)\s+rcon='ban\s+(?P<cid_ban>\d+)\s+(?P<duration>\d+)\s+(?P<reason>[^']+)'$"
    ).unwrap();

    // TODO: how to make this optional?
    static ref CHAT_MAPGEN_START_REGEX: Regex = Regex::new(
        r#".*\[GEN\] Generating.*gen_cfg="(?P<gen_cfg>[^"]+)".*map_cfg="(?P<map_cfg>[^"]+)".*"#
    ).unwrap();
    static ref CHAT_MAPGEN_DONE_REGEX: Regex = Regex::new(
        r"^\*\*\* \[GEN\] Done\.\.\.$"
    ).unwrap();
}

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "Anonymizes and filters ddnet server log files"
)]
struct Args {
    /// Input log file path
    #[arg(short, long)]
    input: String,

    /// Output log file path
    // #[arg(short, long)]
    // output: String,

    /// Whitelist of group names (e.g., ddnet,server,chat). Use comma to separate multiple groups.
    #[arg(short, long, value_delimiter = ',')]
    whitelist: Vec<String>,
}

struct LogParser {
    /// store all finished playsession for each player name
    sessions: HashMap<String, Vec<PlaySession>>,

    /// currently tracked play sessions for all possible CID's
    tracked_sessions: [Option<TrackedPlaySession>; 64],

    /// last joined CID, used for matching player names to CID
    last_join_cid: Option<usize>,

    /// track which CIDs are currently in timeout state
    // cid_timeout: [bool; 64],

    /// TODO: DOC
    last_line_datetime: Option<NaiveDateTime>,
}

#[derive(Debug)]
struct Player {
    name: String,
    sessions: Vec<TrackedPlaySession>,
}

#[derive(Debug)]
struct TrackedPlaySession {
    start: NaiveDateTime,
    end: Option<NaiveDateTime>,
    player_name: Option<String>,
    client_ip: String,
    chat_messages: Vec<String>,
    finishes: Vec<Finish>,
    version: Option<String>,
    timeout: bool,

    /// tracks if player is currently connected. Relevant for players leaving during a map change.
    connected: bool,
}

#[derive(Serialize, Deserialize, Debug)]
struct PlaySession {
    start: NaiveDateTime,
    end: NaiveDateTime,
    duration: usize,
    player_name: String,
    client_ip: String,
    chat_messages: Vec<String>,
    finishes: Vec<Finish>,
    version: String,
    timeout: bool,
}

impl TrackedPlaySession {
    fn new(start: NaiveDateTime, client_ip: String) -> TrackedPlaySession {
        TrackedPlaySession {
            start,
            end: None,
            player_name: None,
            client_ip,
            chat_messages: Vec::new(),
            finishes: Vec::new(),
            version: None,
            timeout: false,
            connected: true,
        }
    }

    fn finalize(self) -> Option<PlaySession> {
        if self.version.is_none() {
            return None; // we dont want to crash here as server may kick old versions..
        }
        let version = self.version.unwrap();

        // however, we want to crash when these are not set
        let end = self.end.expect("end not set");
        let duration = (end - self.start).num_seconds() as usize;
        let player_name = self.player_name.expect("name not set");

        Some(PlaySession {
            start: self.start,
            end,
            duration,
            player_name,
            client_ip: self.client_ip,
            chat_messages: self.chat_messages,
            finishes: self.finishes,
            version,
            timeout: self.timeout,
        })
    }

    fn set_or_validate_name(&mut self, name: &str) {
        if let Some(ref current_name) = self.player_name {
            if current_name == name {
                return;
            }

            // allow name changes from "(1)name" -> "name"
            // allow name changes from "name" -> "(1)name"
            if compare_sanitized_player_names(current_name, name) {
                info!("implicit rename {} -> {}", current_name, name);
                self.player_name = Some(name.to_string());
                return;
            }

            dbg!(sanitize_player_name(current_name));
            dbg!(sanitize_player_name(name));

            warn!(
                "Name mismatch: currently known name is '{}', now '{}'",
                current_name, name
            );
        }

        self.player_name = Some(name.to_string());
    }
}

fn sanitize_player_name(name: &str) -> String {
    if name.starts_with('(') {
        if let Some(end) = name.find(')') {
            let base_name = name[end + 1..].trim();
            let prefix = &name[..end + 1];
            let allowed_length = NAME_LIMIT.saturating_sub(prefix.len());
            return base_name.chars().take(allowed_length).collect();
        }
    }
    name.to_string()
}

fn compare_sanitized_player_names(name_a: &str, name_b: &str) -> bool {
    let san_a = sanitize_player_name(name_a);
    let san_b = sanitize_player_name(name_b);
    let min_len = san_a.chars().count().min(san_b.chars().count());
    san_a.chars().take(min_len).eq(san_b.chars().take(min_len))
}

#[derive(Serialize, Deserialize, Debug)]
struct Finish {
    // map_name: String,
    /// finish time in seconds
    finish_time: f32,
}

#[derive(Debug)]
struct Line {
    date_time: NaiveDateTime,
    group: String,
    message: String,
}

// TODO: move to utils
fn get_single_capture<'a>(regex: &Regex, input: &'a str) -> Option<regex::Captures<'a>> {
    let mut captures = regex.captures_iter(input);
    let cap = match captures.next() {
        Some(c) => c,
        None => return None,
    };
    assert!(
        captures.next().is_none(),
        "Expected exactly one match, found more"
    );
    Some(cap)
}

impl LogParser {
    pub fn new() -> LogParser {
        LogParser {
            sessions: HashMap::new(),
            tracked_sessions: [const { None }; MAX_PLAYERS],
            last_join_cid: None,
            last_line_datetime: None,
        }
    }

    pub fn process_line(&mut self, line: &str) {
        if let Some(line) = Self::parse_line(line) {
            match line.group.as_str() {
                "server" => self.process_server(&line),
                "chat" => self.process_chat(&line),
                "game" => self.process_game(&line),
                "ddnet" => self.process_ddnet(&line),
                "engine" => self.process_engine(&line),
                _ => {}
            };

            // finished processing, now update last seen datetime
            self.last_line_datetime = Some(line.date_time);
        }
    }

    fn parse_line(line: &str) -> Option<Line> {
        let parts: Vec<&str> = line.split_whitespace().collect();

        // sanity check for syntax
        if parts.len() < 4 {
            return None;
        }

        let group = parts[3].strip_suffix(':').unwrap_or(parts[3]);
        let message = parts[4..].join(" ");
        let date_time_string = format!("{} {}", parts[0], parts[1]);

        // there are weird SQL log lines that span across multiple lines. For now,
        // parsing them will fail. In future they should be explicitly dealt with.
        let date_time =
            NaiveDateTime::parse_from_str(&date_time_string, "%Y-%m-%d %H:%M:%S").ok()?;

        Some(Line {
            date_time,
            group: group.to_string(),
            message,
        })
    }

    fn process_server(&mut self, line: &Line) {
        if let Some(cap) = get_single_capture(&SERVER_JOIN_REGEX, &line.message) {
            let cid: usize = cap["client_id"].parse::<usize>().unwrap();
            self.last_join_cid = Some(cid); // remember joined CID
            let ip = &cap["ip"];

            // its possible that a new client connects with a CID that is already tracked.
            // this can for example happen on map change. In this case we check if the IPs match.
            if let Some(tracked_session) = &mut self.tracked_sessions[cid] {
                // first we ensure that tracked connection is not actively connected
                assert!(
                    !tracked_session.connected,
                    "cid={} is already tracked AND connected?",
                    cid
                );

                // then we check if IPs match, if yes we interpret the server join as a re-join and
                // continue the tracked session for this CID
                if tracked_session.client_ip == ip {
                    debug!("server re-join cid={}", cid);
                    tracked_session.connected = true;
                    tracked_session.end = None; // reset end datetime, as player reconnected
                    return; // skip the following
                }

                // if IPs dont match it seems like a new person joined and received a tracked
                // CID for which the server didnt explicitly log a leave. But as its unconnected
                // its safe to assume that the client disconnected. Therefore, we finish the
                // currently recorded session and create a new one for the new join.
                self.finish_session(cid);
            }

            // new CID -> start new session!
            debug!("server join cid={}", cid);
            self.tracked_sessions[cid] =
                Some(TrackedPlaySession::new(line.date_time, ip.to_string()));
        } else if let Some(cap) = get_single_capture(&SERVER_RCON_BAN_REGEX, &line.message) {
            // r"^ClientID=(?P<cid>\d+)\s+rcon='ban\s+(?P<cid_ban>\d+)\s+(?P<duration>\d+)\s+(?P<reason>[^']+)'$"
            let _cid_user: usize = cap["cid"].parse::<usize>().unwrap();
            let cid_ban: usize = cap["cid_ban"].parse::<usize>().unwrap();
            let _duration: usize = cap["duration"].parse::<usize>().unwrap();
            let _reason = &cap["reason"];

            info!("BAN {}!", cid_ban);

            let session = self.get_tracked_session(cid_ban);
            session.end = Some(line.date_time);
            self.finish_session(cid_ban);
        }
    }

    fn process_game(&mut self, line: &Line) {
        if let Some(cap) = get_single_capture(&GAME_LEAVE_REGEX, &line.message) {
            // end active session
            let cid: usize = cap["cid"].parse::<usize>().unwrap();
            let name = &cap["name"];

            debug!("game leave cid={}", cid);

            // add end datetime to session and validate player name
            let session = self.get_tracked_session(cid);
            session.set_or_validate_name(&name);
            if session.end.is_none() {
                // we dont overwrite if aleady set (by timeout)
                session.end = Some(line.date_time);
            }

            // store session
            self.finish_session(cid);
        }
    }

    fn process_chat(&mut self, line: &Line) {
        if let Some(cap) = get_single_capture(&CHAT_MESSAGE_REGEX, &line.message) {
            let cid: usize = cap["cid"].parse::<usize>().unwrap();
            let name = &cap["name"];
            let _unknown = &cap["unknown"]; // TODO: what is this?
            let message = cap["message"].to_string();

            let session = self.get_tracked_session(cid);
            session.set_or_validate_name(&name);
            session.chat_messages.push(message);
        } else if let Some(cap) = get_single_capture(&CHAT_FINISH_REGEX, &line.message) {
            let name = &cap["name"];
            let secs = cap["seconds"].parse::<f32>().unwrap();
            let mins = cap["minutes"].parse::<f32>().unwrap();

            let cid = self.get_cid_sanitized(&name).unwrap();
            let session = self.get_tracked_session(cid);

            let finish = Finish {
                finish_time: (mins * 60.) + secs,
            };

            session.finishes.push(finish);
        } else if let Some(cap) = get_single_capture(&CHAT_JOIN_REGEX, &line.message) {
            let name = &cap["name"];
            let new_cid = self.last_join_cid.unwrap();

            if let Some(old_cid) = self.get_cid_exact(name) {
                // player name is already tracked for another cid. This can happen if a player
                // re-connects while the server map changes. So a leave is never triggered.
                // so we migrate old_cid -> new_cid
                let old_session = self.tracked_sessions[old_cid].as_ref().unwrap();

                if new_cid == old_cid {
                    // not actually any collision, make sure the name is set.
                    self.tracked_sessions[old_cid]
                        .as_mut()
                        .unwrap()
                        .set_or_validate_name(name);
                    debug!(
                        "repeated name join for cid={} with name='{}'",
                        new_cid, name
                    );
                } else if !old_session.connected {
                    self.tracked_sessions[new_cid] = self.tracked_sessions[old_cid].take();
                    debug!("migrating {} -> {}", old_cid, new_cid);
                } else {
                    panic!("collision cids=[{},{}]", old_cid, new_cid);
                }
            } else {
                // current player name is not tracked yet so we use the previous
                // server join message for determining the correct new CID.
                let session = &mut self.get_tracked_session(new_cid);
                session.set_or_validate_name(&name);
                debug!("new join -> {}", new_cid);
            }
        } else if let Some(cap) = get_single_capture(&CHAT_RENAME_REGEX, &line.message) {
            let old_name = &cap["old"];
            let new_name = &cap["new"];
            debug!("rename {} -> {}", old_name, new_name);
            let cid = self.get_cid_exact(&old_name).unwrap();
            let session = self.get_tracked_session(cid);
            session.player_name = Some(new_name.to_string()); // overwrite! TODO: track all names?
        } else if let Some(cap) = get_single_capture(&CHAT_TIMEOUT_REGEX, &line.message) {
            let name = &cap["name"];
            let cid = self.get_cid_exact(&name).unwrap();
            debug!("timeout {} {}", cid, name);

            let session = self.get_tracked_session(cid);
            session.end = Some(line.date_time); // set end in case timeout never reconnects
            session.timeout = true;
        } else if let Some(cap) = get_single_capture(&CHAT_MAPGEN_START_REGEX, &line.message) {
            let gen_cfg = &cap["gen_cfg"];
            let map_cfg = &cap["map_cfg"];
            debug!("started gen {} {}", gen_cfg, map_cfg);
        } else if let Some(cap) = get_single_capture(&CHAT_MAPGEN_DONE_REGEX, &line.message) {
            debug!("gen success");
            // new map was generated
            for cid in 0..MAX_PLAYERS {
                if let Some(tracked_session) = &mut self.tracked_sessions[cid] {
                    // set all connections to not connected, remember end datetime
                    tracked_session.connected = false;
                    tracked_session.end = Some(line.date_time);

                    // and completely cleanup timeouted connections..
                    if tracked_session.timeout {
                        debug!("cleanup timeouted player cid={}", cid);
                        self.finish_session(cid);
                    }
                }
            }
        }
    }

    fn process_ddnet(&mut self, line: &Line) {
        if let Some(cap) = get_single_capture(&DDNET_VERSION_REGEX, &line.message) {
            let cid: usize = cap["cid"].parse::<usize>().unwrap();
            let version = cap["version"].to_string();

            self.get_tracked_session(cid).version = Some(version);
        }
    }

    fn process_engine(&mut self, line: &Line) {
        if let Some(cap) = get_single_capture(&ENGINE_SERVER_START_REGEX, &line.message) {
            // server is restarting so we need to cleanup all running playsessions

            // if there is no previously seen datetime it means that this is the first line of
            // the serverlog, so nothing needs to be cleaned up, just skip
            if self.last_line_datetime.is_none() {
                return;
            }

            debug!("server start, cleaning players");
            for cid in 0..MAX_PLAYERS {
                // set missing datetime
                if let Some(ref mut tracked_session) = &mut self.tracked_sessions[cid] {
                    debug!("finishing player cid={}", cid);
                    // use last datetime before restart
                    if tracked_session.end.is_none() {
                        tracked_session.end = self.last_line_datetime.clone();
                    }
                    self.finish_session(cid);
                }
            }
        }
    }

    fn finish_session(&mut self, cid: usize) {
        let tracked_session = self.tracked_sessions[cid].take().unwrap();

        if let Some(session) = tracked_session.finalize() {
            // TODO: clean player prefixes
            if !self.sessions.contains_key(&session.player_name) {
                self.sessions
                    .insert(session.player_name.to_owned(), Vec::new());
            }
            self.sessions
                .get_mut(&session.player_name)
                .unwrap()
                .push(session);
        } else {
            warn!("session couldnt be finalized");
        }
    }

    fn get_tracked_session(&mut self, cid: usize) -> &mut TrackedPlaySession {
        let session = self.tracked_sessions[cid]
            .as_mut()
            .expect(&format!("no tracked session for cid={}", cid));

        session
    }

    fn get_cid_sanitized(&self, player_name: &str) -> Option<usize> {
        self.tracked_sessions.iter().position(|tracked_session| {
            tracked_session.as_ref().map_or(false, |s| {
                s.player_name
                    .as_ref()
                    .map_or(false, |n| compare_sanitized_player_names(player_name, n))
            })
        })
        // .expect(&format!("No tracked session found for '{}'", player_name))
    }

    fn get_cid_exact(&self, player_name: &str) -> Option<usize> {
        self.tracked_sessions.iter().position(|tracked_session| {
            tracked_session.as_ref().map_or(false, |s| {
                s.player_name.as_ref().map_or(false, |n| n == player_name)
            })
        })
        // .expect(&format!("No tracked session found for '{}'", player_name))
    }
}

fn dump_sessions(sessions: &HashMap<String, Vec<PlaySession>>, output_path: &str) {
    match File::create(output_path) {
        Ok(file) => {
            if let Err(e) = serde_json::to_writer_pretty(file, sessions) {
                error!("Failed to write sessions json: {:?}", e);
            } else {
                info!("Sessions written to {}", output_path);
            }
        }
        Err(e) => error!("Failed to create output file {}: {:?}", output_path, e),
    }
}

fn main() -> std::io::Result<()> {
    env_logger::builder()
        .format_timestamp(None)
        .format_target(false)
        .init();
    let args = Args::parse();
    let mut parser = LogParser::new();

    let count_file = File::open(&args.input)?;
    let count_reader = BufReader::new(count_file);
    let total_lines = count_reader.lines().count() as u64;

    let input_file = File::open(&args.input)?;
    let reader = BufReader::new(input_file);

    for (line_number, line) in reader.lines().enumerate() {
        let line = line?;
        trace!("{}: {}", line_number, line);

        let result = catch_unwind(AssertUnwindSafe(|| {
            parser.process_line(&line);
        }));
        if let Err(err) = result {
            // dbg!(parser.sessions);
            dbg!(parser.tracked_sessions);
            error!("crashed D:");
            dump_sessions(&parser.sessions, "./dump.json");
            panic::resume_unwind(err);
        }
    }

    dbg!(parser.sessions);
    dbg!(parser.tracked_sessions);

    Ok(())
}
