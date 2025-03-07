use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};
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

    /// Whitelist of group names (e.g., ddnet,other). Use comma to separate multiple groups.
    #[arg(short, long, value_delimiter = ',')]
    whitelist: Vec<String>,
}

fn process_chat(line: String) -> Option<String> {
    if !line.starts_with("***") {
        return None;
    }
    Some(line)
}

fn main() -> std::io::Result<()> {
    let args = Args::parse();

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

        let processed_message = match group {
            "chat" => process_chat(message),
            _ => Some(message),
        };

        if let Some(message) = processed_message {
            let output_line = format!("{} {} I {}: {}", date, time, group, message);
            writeln!(output_file, "{}", output_line)?;
        }
    }
    progress.finish();
    Ok(())
}
