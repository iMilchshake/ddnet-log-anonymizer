use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};
use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};

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

struct Anonymizer {
    player_names: HashSet<String>,
    dropped_lines: usize,
}

impl Anonymizer {
    fn new() -> Anonymizer {
        Anonymizer {
            player_names: HashSet::new(),
            dropped_lines: 0,
        }
    }

    fn process_line(&mut self, group: &str, message: String) -> Option<String> {
        match group {
            "chat" => self.process_chat(message),
            _ => Some(message),
        }
    }

    fn process_chat(&mut self, message: String) -> Option<String> {
        // chat messages dont start with ***, we drop those
        if !message.starts_with("***") {
            return None;
        }

        // extract player names from join messages
        if message.contains("entered and joined the game") {
            if let Some(start) = message.find('\'') {
                if let Some(end) = message[start + 1..].find('\'') {
                    let player_name = &message[start + 1..start + 1 + end];
                    self.player_names.insert(player_name.to_string());
                }
            }
        }

        Some(message)
    }
}

fn main() -> std::io::Result<()> {
    let args = Args::parse();
    let mut anon = Anonymizer::new();

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

        // sanity check for syntax
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 {
            progress.println(format!(
                "Warning: Line {} does not have expected format: {}",
                line_number + 1,
                line
            ));
            continue;
        }

        let date = parts[0];
        let time = parts[1];
        let group = parts[3].strip_suffix(':').unwrap_or(parts[3]); // TODO:
        let message = parts[4..].join(" ");

        // check group whitelist
        if !args.whitelist.contains(&group.to_string()) {
            continue;
        }

        let processed_message = anon.process_line(group, message);

        if let Some(message) = processed_message {
            let output_line = format!("{} {} I {}: {}", date, time, group, message);
            writeln!(output_file, "{}", output_line)?;
        }
    }
    progress.finish();
    Ok(())
}
