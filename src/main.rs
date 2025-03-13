use chrono::{DateTime, Duration, NaiveDateTime, TimeZone, Utc};

use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};
use std::fs::File;
use std::io::{BufRead, BufReader, Write};

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
    #[arg(short, long)]
    output: String,

    /// Whitelist of group names (e.g., ddnet,server,chat). Use comma to separate multiple groups.
    #[arg(short, long, value_delimiter = ',')]
    whitelist: Vec<String>,
}

struct Player {
    name: Option<String>,
    client_id: usize,
    ip: String,
}

struct PlaySession {
    start: DateTime<Utc>,
    duration: Option<Duration>,
    player_name: Option<String>,
    client_id: usize,
    client_ip: String,
}

#[derive(Debug)]
struct Line {
    date_time: DateTime<Utc>,
    group: String,
    message: String,
}

struct LogParser {
    players: [Option<Player>; MAX_PLAYERS],
}

impl LogParser {
    fn new() -> LogParser {
        LogParser {
            players: [const { None }; MAX_PLAYERS],
        }
    }

    pub fn parse_line(line: String) -> Option<Line> {
        let parts: Vec<&str> = line.split_whitespace().collect();

        // sanity check for syntax
        if parts.len() < 4 {
            return None;
        }

        let group = parts[3].strip_suffix(':').unwrap_or(parts[3]); // TODO:
        let message = parts[4..].join(" ");

        let date_time_string = format!("{} {}", parts[0], parts[1]);
        let naive_date_time =
            NaiveDateTime::parse_from_str(&date_time_string, "%Y-%m-%d %H:%M:%S").unwrap();
        let utc_date_time: DateTime<Utc> = Utc.from_utc_datetime(&naive_date_time);

        Some(Line {
            date_time: utc_date_time,
            group: group.to_string(),
            message,
        })
    }

    fn process_line(&mut self, line: &Line) {
        match line.group.as_str() {
            "chat" => self.process_chat(&line.message),
            _ => {}
        };
    }

    fn process_chat(&mut self, message: &str) {
        // chat messages dont start with ***, we drop those
        if !message.starts_with("***") {
            return;
        }

        // extract player names from join messages
        if message.contains("entered and joined the game") {
            if let Some(start) = message.find('\'') {
                if let Some(end) = message[start + 1..].find('\'') {
                    let player_name = &message[start + 1..start + 1 + end];
                    // self.player_names.insert(player_name.to_string());
                }
            }
        }
    }
}

fn main() -> std::io::Result<()> {
    let args = Args::parse();
    let mut anon = LogParser::new();

    let count_file = File::open(&args.input)?;
    let count_reader = BufReader::new(count_file);
    let total_lines = count_reader.lines().count() as u64;

    let progress = ProgressBar::new(total_lines);
    progress.set_style(
        ProgressStyle::with_template("{msg} [{bar:40}] {pos}/{len} ETA: {eta}")
            .unwrap()
            .progress_chars("=>-"),
    );

    let input_file = File::open(&args.input)?;
    let reader = BufReader::new(input_file);
    let mut output_file = File::create(&args.output)?;

    for (line_number, line) in reader.lines().enumerate() {
        let line = line?;
        progress.inc(1);

        let processed_message = LogParser::parse_line(line);
        dbg!(processed_message);
    }

    progress.finish();
    Ok(())
}
