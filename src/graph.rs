use petgraph::prelude::*;
use petgraph::Direction;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use anyhow::Result;
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum NodeKind {
    Firmware { id: String },
    Binary { id: String, path: String },
    Function { addr: String, name: String },
    String { addr: String, value: String },
    Library { name: String },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum EdgeKind {
    Contains,
    Calls,
    UsesString,
    UsesLib,
}

pub type FwGraph = Graph<NodeKind, EdgeKind>;

pub fn build_graph(
    firmware_id: &str,
    analysis_dir: &Path,
) -> Result<(FwGraph, Vec<String>)> {
    let mut graph = FwGraph::new();
    
    let firmware_node = graph.add_node(NodeKind::Firmware {
        id: firmware_id.to_string(),
    });+}
    
    let mut binary_to_node: HashMap<String, NodeIndex> = HashMap::new();
    
    for entry in std::fs::read_dir(analysis_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().map_or(false, |e| e == "json") {
            let data: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&path)?)?;
            let bin_id = path.file_stem().unwrap().to_str().unwrap();
            
            // Add Binary node
            let binary_node = graph.add_node(NodeKind::Binary {
                id: bin_id.to_string(),
                path: format!("{}", path.display()),
            });
            graph.add_edge(firmware_node, binary_node, EdgeKind::Contains);
            binary_to_node.insert(bin_id.to_string(), binary_node);
            
            // Add Functions
            let mut func_to_node: HashMap<String, NodeIndex> = HashMap::new();
            for func in data["functions"].as_array().unwrap() {
                let func_node = graph.add_node(NodeKind::Function {
                    addr: func["addr"].as_str().unwrap().to_string(),
                    name: func["name"].as_str().unwrap().to_string(),
                });
                graph.add_edge(binary_node, func_node, EdgeKind::Contains);
                func_to_node.insert(func["addr"].as_str().unwrap().to_string(), func_node);
            }
            
            // Add Call edges
            for call in data["calls"].as_array().unwrap() {
                let caller_addr = call["caller"].as_str().unwrap();
                let callee_addr = call["callee"].as_str().unwrap();
                
                if let (Some(caller_node), Some(callee_node)) = 
                    (func_to_node.get(caller_addr), func_to_node.get(callee_addr)) {
                    graph.add_edge(*caller_node, *callee_node, EdgeKind::Calls);
                }
            }
            
            // Add Strings
            for str_ref in data["strings"].as_array().unwrap() {
                let str_node = graph.add_node(NodeKind::String {
                    addr: str_ref["addr"].as_str().unwrap().to_string(),
                    value: str_ref["value"].as_str().unwrap().to_string(),
                });
                
                if let Some(first_func) = func_to_node.values().next() {
                    graph.add_edge(*first_func, str_node, EdgeKind::UsesString);
                }
            }
            
            // Add Imports → Libraries
            let mut lib_cache: HashMap<String, NodeIndex> = HashMap::new();
            for import in data["imports"].as_array().unwrap() {
                let lib_name = import["name"].as_str().unwrap().to_string();
                
                let lib_node = if let Some(&node) = lib_cache.get(&lib_name) {
                    node
                } else {
                    let new_node = graph.add_node(NodeKind::Library {
                        name: lib_name.clone(),
                    });
                    lib_cache.insert(lib_name, new_node);
                    new_node
                };
                
                if let Some(func_node) = func_to_node.values().next() {
                    graph.add_edge(*func_node, lib_node, EdgeKind::UsesLib);
                }
            }
        }
    }
    
    // Validation stats
    let mut stats = Vec::new();
    stats.push(format!("Firmware nodes: {}", graph.node_count()));
    stats.push(format!("Firmware edges: {}", graph.edge_count()));
    
    Ok((graph, stats))
}