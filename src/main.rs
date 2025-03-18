use chrono::{Duration, NaiveDateTime};

use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};
use lazy_static::lazy_static;
use regex::Regex;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};

const MAX_PLAYERS: usize = 64;

// TODO: move to some clean regex handler struct
lazy_static! {
    static ref SERVER_JOIN_REGEX: Regex = Regex::new(
        r"(?m)^player has entered the game\. ClientID=(?P<client_id>\d+)\s+addr=<\{(?P<ip>\[[^\]]+\]|[^:]+):(?P<port>\d+)\}>\s+sixup=(?P<sixup>[01])$"
    ).unwrap();
    static ref GAME_LEAVE_REGEX: Regex = Regex::new(
        r"(?m)^leave player='(?P<cid>\d+):(?P<name>[^']+)'$"
    ).unwrap();
    static ref CHAT_MESSAGE_REGEX: Regex = Regex::new(
        r"(?m)^(?P<cid>\d+):(?P<unknown>[^:]+):(?P<name>[^:]+): (?P<message>.*)$"
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

    tracked_sessions: [Option<TrackedPlaySession>; 64],
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
}

#[derive(Debug)]
struct PlaySession {
    start: NaiveDateTime,
    end: NaiveDateTime,
    duration: Duration,
    player_name: String,
    client_ip: String,
    chat_messages: Vec<String>,
    finishes: Vec<Finish>,
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
        }
    }

    fn finalize(self) -> PlaySession {
        let end = self.end.expect("end not set");
        let player_name = self.player_name.expect("name not set");
        let duration = end - self.start;
        PlaySession {
            start: self.start,
            end,
            duration,
            player_name,
            client_ip: self.client_ip,
            chat_messages: self.chat_messages,
            finishes: self.finishes,
        }
    }

    fn set_or_validate_name(&mut self, name: &str) {
        if let Some(ref set_name) = self.player_name {
            assert_eq!(set_name, name);
        } else {
            self.player_name = Some(name.to_string());
        }
    }
}

#[derive(Debug)]
struct Finish {
    map_name: String,
    finish_time: Duration,
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
        }
    }

    pub fn process_line(&mut self, line: &str) {
        if let Some(line) = Self::parse_line(line) {
            match line.group.as_str() {
                "server" => self.process_server(&line),
                "chat" => self.process_chat(&line),
                "game" => self.process_game(&line),
                _ => {}
            };
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
            let ip = &cap["ip"];

            println!("start {}", cid);

            // there is no explicit signal for map changes, but implied by cid collisions
            if self.tracked_sessions[cid].is_some() {
                return; // skip TODO: check if there was a pending vote?
            }

            // start new session
            self.tracked_sessions[cid] =
                Some(TrackedPlaySession::new(line.date_time, ip.to_string()));
        }
    }

    fn process_game(&mut self, line: &Line) {
        if let Some(cap) = get_single_capture(&GAME_LEAVE_REGEX, &line.message) {
            // end active session
            let cid: usize = cap["cid"].parse::<usize>().unwrap();
            let name = &cap["name"];

            println!("end {}", cid);

            // add missing player name and end datetime to session
            let session = self.get_tracked_session(cid);
            session.set_or_validate_name(&name);
            session.end = Some(line.date_time);

            // store session
            self.finish_session(cid);
        }
    }

    fn process_chat(&mut self, line: &Line) {
        if let Some(cap) = get_single_capture(&CHAT_MESSAGE_REGEX, &line.message) {
            let cid: usize = cap["cid"].parse::<usize>().unwrap();
            let name = &cap["name"];
            let _unknown = &cap["unknown"];
            let message = cap["message"].to_string();

            let session = self.get_tracked_session(cid);
            session.set_or_validate_name(&name);
            session.chat_messages.push(message);
        }
    }

    fn finish_session(&mut self, cid: usize) {
        let tracked_session = self.tracked_sessions[cid].take().unwrap();
        let session = tracked_session.finalize();

        // TODO: clean player prefixes
        if !self.sessions.contains_key(&session.player_name) {
            self.sessions
                .insert(session.player_name.to_owned(), Vec::new());
        }

        self.sessions
            .get_mut(&session.player_name)
            .unwrap()
            .push(session);
    }

    fn get_tracked_session(&mut self, cid: usize) -> &mut TrackedPlaySession {
        let session = self.tracked_sessions[cid]
            .as_mut()
            .expect(&format!("no tracked session for cid={}", cid));

        session
    }
}

fn main() -> std::io::Result<()> {
    let args = Args::parse();
    let mut parser = LogParser::new();

    let count_file = File::open(&args.input)?;
    let count_reader = BufReader::new(count_file);
    let total_lines = count_reader.lines().count() as u64;

    let input_file = File::open(&args.input)?;
    let reader = BufReader::new(input_file);

    for (line_number, line) in reader.lines().enumerate() {
        let line = line?;
        println!("{}", &line);
        println!("{}: {}", line_number, line);
        parser.process_line(&line);

        // println!("\n");
    }

    dbg!(parser.sessions);
    dbg!(parser.tracked_sessions);

    Ok(())
}
