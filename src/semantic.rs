use crate::analysis::{AnalysisResult, Function};
use regex::Regex;
use std::collections::HashMap;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FunctionTags {
    pub network_source: bool,
    pub memcopy_sink: bool,
    pub crypto_usage: bool,
    pub constant_key: bool,
}

ub fn tag_functions(analysis: &AnalysisResult) -> HashMap<String, FunctionTags> {
    let mut tagged = HashMap::new();
    
    let network_re = Regex::new(r"(socket|bind|accept|listen|recv|send)").unwrap();
    let memcopy_re = Regex::new(r"(memcpy|memmove|strcpy|strcat)").unwrap();
    let crypto_re = Regex::new(r"(AES|SHA|SSL|DES|RC4|mbedtls)").unwrap();
    
    for func in &analysis.functions {
        let func_name = func.name.to_lowercase();
        let mut tags = FunctionTags {
            network_source: false,
            memcopy_sink: false,
            crypto_usage: false,
            constant_key: false,
        };
        
        for import in &analysis.imports {
            let imp_name = import.name.to_lowercase();
            
            if network_re.is_match(&imp_name) {
                tags.network_source = true;
            }
            if memcopy_re.is_match(&imp_name) {
                tags.memcopy_sink = true;
            }
            if crypto_re.is_match(&imp_name) {
                tags.crypto_usage = true;
            }
        }
        
        // functions calling memcpy with string constants nearby = constant_key risk
        if tags.crypto_usage && tags.memcopy_sink {
            tags.constant_key = true;
        }
        
        tagged.insert(func.addr.clone(), tags);
    }
    
    tagged
}

pub fn apply_tags_to_graph(graph: &mut crate::FwGraph, analysis_dir: &std::path::Path) -> anyhow::Result<()> {
    for entry in std::fs::read_dir(analysis_dir)? {
        let path = entry?.path();
        if let Ok(analysis) = crate::analysis::AnalysisResult::deserialize_from_file(&path) {
            let tags = tag_functions(&analysis);
            
            // Log Findings
            for (addr, tags) in tags {
                if tags.network_source && tags.memcopy_sink {
                    println!("RCE candidate: {} (network→memcpy)", addr);
                }
            }
        }
    }
    Ok(())
}