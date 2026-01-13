use std::path::{Path, PathBuf};
use std::process::Command;
use serde::{Deserialize, Serialize};
use anyhow::Result;

#[derive(Serialize, Deserialize, Debug)]
pub struct AnalysisResult {
    pub functions: Vec<Function>,
    pub calls: Vec<CallEdge>,
    pub strings: Vec<StringRef>,
    pub imports: Vec<ImportRef>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Function {
    pub addr: String,
    pub name: String,
    pub size: usize,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CallEdge {
    pub caller: String,
    pub callee: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct StringRef {
    pub addr: String,
    pub value: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ImportRef {
    pub name: String,
    pub addr: String,
}

pub fn analyze_binary(binary_path: &Path, output_path: &Path, ghidra_home: &str) -> Result<()> {
    let script_path = Path::new(ghidra_home).join("Ghidra/Features/Python/data/export_fw.py");
    
    let status = Command::new(format!("{}/analyzeHeadless", ghidra_home))
        .args(&[
            "/tmp/ghidra_proj",  // temp project dir
            "temp_proj",
            "-import", binary_path.to_str().unwrap(),
            "-postScript", script_path.to_str().unwrap(),
            "-deleteProject",
            output_path.to_str().unwrap(),
        ])
        .status()?;
    
    if !status.success() {
        anyhow::bail!("Ghidra analysis failed: {}", status);
    }
    Ok(())
}
