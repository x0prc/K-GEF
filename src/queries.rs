use neo4rs::*;
use anyhow::Result;
use prettytable::Table;
use prettytable::row::Row;

pub async fn run_query(graph: Graph, firmware_id: &str, query_type: &str) -> Result<()> {
    match query_type {
        "rce-candidates" => query_rce_candidates(graph, firmware_id).await?,
        "crypto-risks" => query_crypto_risks(graph, firmware_id).await?,
        "vuln-libs" => query_vuln_libs(graph, firmware_id).await?,
        _ => println!("Available queries: rce-candidates, crypto-risks, vuln-libs"),
    }
    Ok(())
}

async fn query_rce_candidates(mut graph: Graph, firmware_id: &str) -> Result<()> {
    println!("Top RCE Candidates:");
    let mut table = Table::new();
    table.add_row(row!["Source Func", "Sink Func", "Call Distance", "Risk"]);

    let rows = graph
        .query()
        .raw(
            "MATCH (f:Firmware {id: $fw_id})-[:CONTAINS*1..2]->(src:Function)
             WHERE toLower(src.name) CONTAINS 'socket' OR toLower(src.name) CONTAINS 'bind'
             OPTIONAL MATCH path=(src)-[:CALLS*1..4]-(sink:Function)
             WHERE toLower(sink.name) CONTAINS 'memcpy' OR toLower(sink.name) CONTAINS 'strcpy'
             RETURN src.name, sink.name, length(path) as distance, 
                    CASE WHEN sink.name IS NOT NULL THEN 'HIGH' ELSE 'MED' END as risk
             ORDER BY distance ASC LIMIT 20",
            params! { "fw_id" => firmware_id }
        )
        .await?;

    for row in rows {
        let source = row.get::<String>("src.name").unwrap_or_default();
        let sink = row.get::<String>("sink.name").unwrap_or_default();
        let distance = row.get::<i64>("distance").unwrap_or_default();
        let risk = row.get::<String>("risk").unwrap_or_default();
        
        table.add_row(row![source, sink, distance, risk]);
    }
    table.printstd();
    Ok(())
}

async fn query_crypto_risks(mut graph: Graph, firmware_id: &str) -> Result<()> {
    println!("Crypto Risk Assessment:");
    let mut table = Table::new();
    table.add_row(row!["Function", "Lib Used", "Risk Factors"]);

    let rows = graph
        .query()
        .raw(
            "MATCH (f:Firmware {id: $fw_id})-[:CONTAINS*]->(fn:Function)-[:CALLS|USES_LIB*]->(lib:Library)
             WHERE toLower(fn.name) CONTAINS 'crypto' OR toLower(lib.name) CONTAINS 'ssl'
             RETURN fn.name, lib.name, count(lib) as lib_count
             ORDER BY lib_count DESC LIMIT 15",
            params! { "fw_id" => firmware_id }
        )
        .await?;

    for row in rows {
        table.add_row(row![
            row.get::<String>("fn.name").unwrap_or_default(),
            row.get::<String>("lib.name").unwrap_or_default(),
            row.get::<i64>("lib_count").unwrap_or_default()
        ]);
    }
    table.printstd();
    Ok(())
}

async fn query_vuln_libs(mut graph: Graph, firmware_id: &str) -> Result<()> {
    // Static CVE mapping
    let vuln_libs = vec!["openssl < 1.1.1", "libcurl < 7.80", "busybox"];
    
    println!("Vulnerable Libraries:");
    let mut table = Table::new();
    table.add_row(row!["Library", "Firmware Modules", "Known Issues"]);

    let rows = graph
        .query()
        .raw(
            "MATCH (f:Firmware {id: $fw_id})-[:CONTAINS*]->(b:Binary)-[:CONTAINS*]->(fn:Function)-[:USES_LIB]->(lib:Library)
             RETURN lib.name, count(DISTINCT b) as module_count
             ORDER BY module_count DESC LIMIT 10",
            params! { "fw_id" => firmware_id }
        )
        .await?;

    for row in rows {
        let lib_name = row.get::<String>("lib.name").unwrap_or_default();
        table.add_row(row![
            lib_name.clone(),
            row.get::<i64>("module_count").unwrap_or_default(),
            if vuln_libs.iter().any(|v| lib_name.contains(v)) { "CVE" } else { "OK" }
        ]);
    }
    table.printstd();
    Ok(())
}
