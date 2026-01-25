use neo4rs::*;
use crate::graph::{FwGraph, NodeKind, EdgeKind};
use anyhow::Result;

pub async fn connect(uri: &str, user: &str, pass: &str) -> Result<Graph> {
    let graph = Graph::new_async(uri).await?;
    graph.connect(user, pass).await?;
    Ok(graph)
}

pub async fn load_graph(graph: Graph, fw_graph: &FwGraph, firmware_id: &str) -> Result<()> {
    // Clear previous data for this firmware
    let mut tx = graph.start_tx().await?;
    tx.run(
        "MATCH (f:Firmware {id: $id}) DETACH DELETE f",
        params! { "id" => firmware_id }
    ).await?;
    tx.commit().await?;
    
    let mut tx = graph.start_tx().await?;
    
    tx.run(
        "CREATE (f:Firmware {id: $id})",
        params! { "id" => firmware_id }
    ).await?;
    
    // Add other nodes (Binary, Function, etc.) - simplified batch
    for node in fw_graph.node_weights() {
        match node {
            NodeKind::Binary { id, path } => {
                tx.run(
                    "MATCH (f:Firmware {id: $fw_id}) 
                     MERGE (b:Binary {id: $id, path: $path})
                     MERGE (f)-[:CONTAINS]->(b)",
                    params! { "fw_id" => firmware_id, "id" => id, "path" => path }
                ).await?;
            }
            NodeKind::Function { addr, name } => {
                tx.run(
                    "MERGE (fn:Function {addr: $addr, name: $name})",
                    params! { "addr" => addr, "name" => name }
                ).await?;
            }
            NodeKind::Library { name } => {
                tx.run(
                    "MERGE (l:Library {name: $name})",
                    params! { "name" => name }
                ).await?;
            }
            _ => {} 
        }
    }
    
    tx.commit().await?;
    println!("Graph loaded into Neo4j!");
    Ok(())
}

pub async fn query_rce_candidates(graph: Graph, firmware_id: &str) -> Result<()> {
    let rows = graph
        .query()
        .raw(
            "MATCH (f:Firmware {id: $fw_id})-[:CONTAINS*1..2]->(fn:Function)
             WHERE fn.name CONTAINS 'socket' OR fn.name CONTAINS 'bind'
             OPTIONAL MATCH (fn)-[:CALLS*1..3]->(sink:Function)
             WHERE sink.name CONTAINS 'memcpy' OR sink.name CONTAINS 'strcpy'
             RETURN fn.name as source, sink.name as sink, count(sink) as risk_score
             ORDER BY risk_score DESC LIMIT 10",
            params! { "fw_id" => firmware_id }
        )
        .await?;
    
    println!("Top RCE Candidates:");
    for row in rows {
        println!("  {} → {} (risk: {})", 
            row.get::<String>("source").unwrap_or_default(),
            row.get::<String>("sink").unwrap_or_default(),
            row.get::<i64>("risk_score").unwrap_or_default()
        );
    }
    Ok(())
}