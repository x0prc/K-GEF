use std::path::PathBuf;
use std::process::Command;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "K-GEF", version = "0.1", author = "0xprc", about = "Knowledge-Graph Driven Firmware Analysis")]

struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Unpack {
        #[arg(short, long)]
        input: PathBuf,

        #[arg(short, long)]
        out: PathBuf,
    },
}

