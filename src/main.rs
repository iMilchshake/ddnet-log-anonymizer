use chrono::{DateTime, Duration, NaiveDateTime};

use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};
use regex::Regex;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};

const MAX_PLAYERS: usize = 64;

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

    active_sessions: [Option<PlaySession>; 64],
}

#[derive(Debug)]
struct Player {
    name: String,
    sessions: Vec<PlaySession>,
}

#[derive(Debug)]
struct PlaySession {
    start: NaiveDateTime,
    duration: Option<Duration>,
    player_name: Option<String>,
    client_ip: String,
    chat_messages: Vec<String>,
    finishes: Vec<Finish>,
}

impl PlaySession {
    fn new(start: NaiveDateTime, client_ip: String) -> PlaySession {
        PlaySession {
            start,
            duration: None,
            player_name: None,
            client_ip,
            chat_messages: Vec::new(),
            finishes: Vec::new(),
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
            active_sessions: [const { None }; MAX_PLAYERS],
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

    fn process_chat(&mut self, line: &Line) {
        // chat messages dont start with ***, we drop those
        if !line.message.starts_with("***") {
            return;
        }
    }

    fn process_server(&mut self, line: &Line) {
        let server_join_regex = Regex::new(
        r"(?m)^player has entered the game\. ClientID=(?P<client_id>\d+)\s+addr=<\{(?P<ip>\[[^\]]+\]|[^:]+):(?P<port>\d+)\}>\s+sixup=(?P<sixup>[01])$"
        ).unwrap();

        if let Some(cap) = get_single_capture(&server_join_regex, &line.message) {
            let cid: usize = cap["client_id"].parse::<usize>().unwrap();
            let ip = &cap["ip"];

            println!("start {}", cid);

            // there is no explicit signal for map changes, but implied by cid collisions
            if self.active_sessions[cid].is_some() {
                return; // skip TODO: check if there was a pending vote?
            }

            // start new session
            self.active_sessions[cid] = Some(PlaySession::new(line.date_time, ip.to_string()));
        }
    }

    fn process_game(&mut self, line: &Line) {
        let game_leave_regex =
            Regex::new(r"(?m)^leave player='(?P<cid>\d+):(?P<name>[^']+)'$").unwrap();

        if let Some(cap) = get_single_capture(&game_leave_regex, &line.message) {
            // end active session
            let cid: usize = cap["cid"].parse::<usize>().unwrap();
            let name = &cap["name"];

            println!("end {}", cid);

            // add missing player name to session
            let session = self.active_sessions[cid]
                .as_mut()
                .expect(&format!("no active session for cid={}", cid));
            session.player_name = Some(name.to_string());

            // store session
            self.finish_session(cid);
        }
    }

    fn finish_session(&mut self, cid: usize) {
        let session = self.active_sessions[cid].take().unwrap();
        let name = session.player_name.as_ref().expect("player name not set!");

        if !self.sessions.contains_key(name) {
            self.sessions.insert(name.to_string(), Vec::new());
        }
        self.sessions.get_mut(name).unwrap().push(session);
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
        // println!("{}", &line);
        println!("{}: {}", line_number, line);
        parser.process_line(&line);

        // println!("\n");
    }

    dbg!(parser.sessions);
    dbg!(parser.active_sessions);

    Ok(())
}
