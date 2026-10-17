//! piso-hotspot: pay-per-usage wifi hotspot.

mod config;
mod doctor;
mod iwlist;
#[allow(dead_code)] // MAC parsing first has consumers in the paywall/panel (P1+)
mod mac;
mod passes;
mod store;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "piso-hotspot", version, about = "Pay-per-usage wifi hotspot")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Inspect this machine and report what could work. Changes nothing.
    Doctor {
        /// Print the report as JSON.
        #[arg(long)]
        json: bool,
    },
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Command::Doctor { json } => {
            let report = doctor::inspect();
            if json {
                match serde_json::to_string_pretty(&report) {
                    Ok(text) => println!("{text}"),
                    Err(e) => {
                        eprintln!("piso-hotspot: cannot serialize report: {e}");
                        std::process::exit(2);
                    }
                }
            } else {
                doctor::print_human(&report);
            }
            if !report.ok {
                std::process::exit(1);
            }
        }
    }
}
