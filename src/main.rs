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
    // unpack firmware images
    Unpack {
        #[arg(short, long)]
        input: PathBuf,

        #[arg(short, long)]
        out: PathBuf,
    },

    // index ELF binaries 
    Index {
        #[arg(short, long)]
        root: PathBuf,
    }, 

    // export JSON via Ghidra
    Analyze {
        #[arg(short, long)]
        root: PathBuf,

        #[arg(short, long)]
        analysis_out: PathBuf,
    },

    // build graph to Neo4j
    LoadGraph {
        #[arg(short = 'i', long)]
        firmware_id: String,

        #[arg(short, long)]
        analysis_root: PathBuf,
    },

    // canned security queries
    Query {
        #[arg(short = 'i', long)]
        firmware_id: String,

        #[arg(short, long)]
        kind: String
    },
}

#[tokio::main]
async fn main() -> Result <()> {
    init_tracing()?;

    let cli = Cli::parse();

    match cli.command {
        Commands::Unpack {input, out} => cmd_unpack(&input, &out)?,
        Commands::Index {root} => cmd_index(&root)?,
        Commands::Index { root } => fwgraph_firmware::firmware::index_binaries(&root)?,
        Commands::Analyze {root, analysis_out} => cmd_analyze(&root, &analysis_out)?,
        Commands::LoadGraph {
            firmware_id,
            analysis_root,
        } => cmd_load_graph(&firmware_id, &analysis_root).await?,
        Commands::Query {firmware_id, kind} => cmd_query(&firmware_id, &kind).await?,
    }

    Ok (())

}

// Unpack : binwalk wrapper
fn cmd_unpack(input: &PuthBuf, out: &PathBuf) -> Result<()> {
    tracing::info!("Unpacking {:?} into {:?}", input, out);
    
    std::fs::create_dir_all(out).context("output directory creation failed")?,

    let status = Command::new("binwalk")
        .arg("-e")
        .arg(input)
        .current_dir(out)
        .status()
        .context("failed to run binwalk")?,

    if !status.success() {
        anyhow::bail!("binwalk exited with status: {status}");
    }

    tracing::info!("Unpack completed");
    Ok(())
}

