use std::path::{Path, PathBuf};
use walkdir::WalkDir;
use goblin::elf::Elf;
use serde::{Deserialize, Serialize};
use anyhow::Result;

#[derive(Serialize, Deserialize, Debug)]
pub struct BinaryInfo {
    pub id: String, 
    pub path: PathBuf,
    pub arc: String,
    pub size: u64,
}

pub fn unpack_firmware(input: &Path, out_dir: &Path) -> Result<()> {
    std::fs::create_dir_all(out_dir)?;

    let status = std::process::Command::new("binwalk")
        .arg("-e")
        .arg(input)
        .current_dir(out_dir)
        .status()?;

    if !status.success() {
        anyhow::bail!("Binwalk failed with status: {}", status);
    }
    Ok(())
}

pub fn index_binaries(root: &Path) -> Result<Vec<BinaryInfo>> {
    let mut binaries = Vec::new();
    let mut counter = 0;

    for entry in WalkDir::new(root).follow_links(true) {
        let entry = entry?;
        if entry.file_type().is_file() {
            if let Ok(bytes) = std::fs::read(&entry.path()) {
                if let Ok(elf) = Elf::parse(&bytes) {
                    counter += 1;
                    binaries.push(BinaryInfo {
                        id: format!("bin_{:03}", counter),
                        path: entry_path().strip_prefix(root)?.to_path_buf(),
                        arch: format!("{:?}", elf.header.e_machine),
                        size: bytes.len() as u64,
                    });
                }
            }
        }
    }

    let path = root.join("binaries.json");
    std::fs::write(&path, serde_json::to_string_pretty(&binaries)?)?;

    println!("Found {} ELF binaries -> {}", binaries.len(), path.display());
    Ok(binaries)
}
