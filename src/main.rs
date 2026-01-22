use std::path::PathBuf;
use std::process::Command;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

mod firmware;
mod analysis;
mod graph;
use firmware::*;
use analysis::*;
use graph::*;

#[derive(Parser, Debug)]
#[command(name = "K-GEF", version = "0.1", author = "0xprc", about = "Knowledge-Graph Driven Firmware Analysis")]


struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Unpack a firmware image (binwalk) into an output directory
    Unpack {
        #[arg(short, long)]
        input: PathBuf,

        #[arg(short, long)]
        out: PathBuf,
    },

    /// Index ELF binaries in an extracted firmware tree
    Index {
        #[arg(short, long)]
        root: PathBuf,
    },

    /// Run Ghidra headless analysis and export JSON
    Analyze {
        #[arg(short, long)]
        root: PathBuf,

        #[arg(short, long)]
        analysis_out: PathBuf,

        #[arg(short = 'g', long, default_value = "/opt/ghidra")]
        ghidra_home: PathBuf,
    },

    /// Build in-memory graph from analysis results
    GraphBuild {
        #[arg(short, long)]
        firmware_id: String,

        #[arg(short, long)]
        analysis_dir: PathBuf,
    },

    /// Apply Semantic tagging
    GraphTag {
        #[arg(short, long)]
        firmware_id: String,
        #[arg(short, long)]
        analysis_dir: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing()?;

    let cli = Cli::parse();

    match cli.command {
        Commands::Unpack { input, out } => unpack_firmware(&input, &out)?,
        Commands::Index { root } => {
            let binaries = index_binaries(&root)?;
            println!("Found {} ELF binaries", binaries.len());
        }
        Commands::Analyze { 
            root, 
            analysis_out, 
            ghidra_home 
        } => analyze_all(&root, &analysis_out, ghidra_home.to_str().unwrap())?,
        Commands::GraphBuild { 
            firmware_id, 
            analysis_dir 
        } => {
            let (graph, stats) = build_graph(&firmware_id, &analysis_dir)?;
            let out_path = analysis_dir.join(format!("{}.graph.json", firmware_id));
            std::fs::write(&out_path, serde_json::to_string_pretty(&graph)?)?;
            println!("Graph saved: {} | {}", out_path.display(), stats.join(", "));
        }
        Commands::GraphTag { firmware_id: _, analysis_dir } => {
            semantic_tag_analysis(&analysis_dir)?;
            println!("Complete.");
        }
    }

    Ok(())
}

fn init_tracing() -> Result<()> {
    let filter = EnvFilter::from_default_env()
        .add_directive("fwgraph_firmware=info".parse().unwrap());
    tracing_subscriber::fmt().with_env_filter(filter).init();
    Ok(())
}

fn semantic_tag_analysis(analysis_dir: &PathBuf) -> Result<()> {
    println!("Scanning...");
    apply_tags_to_graph(&analysis_dir)?;
    Ok(())
}