use std::env;

use oracle_rs::{Config, Connection};

#[tokio::main]
async fn main() -> oracle_rs::Result<()> {
    let host = env::var("ORACLE_HOST").unwrap_or_else(|_| "localhost".to_string());
    let port = env::var("ORACLE_PORT")
        .ok()
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(1521);
    let service = env::var("ORACLE_SERVICE_NAME").unwrap_or_else(|_| "xe".to_string());
    let username = env::var("ORACLE_USERNAME").expect("ORACLE_USERNAME not set");
    let password = env::var("ORACLE_PASSWORD").expect("ORACLE_PASSWORD not set");

    let config = Config::new(host, port, service, username, password);
    let conn = Connection::connect_with_config(config).await?;
    let server = conn.server_info().await;

    println!("protocol_version={}", server.protocol_version);
    println!("banner={}", server.banner);

    let result = conn.query("SELECT 1 FROM DUAL", &[]).await?;
    println!("rows={}", result.rows.len());
    if let Some(row) = result.rows.first() {
        if let Some(value) = row.get(0) {
            println!("value={value}");
        }
    }

    conn.close().await?;
    Ok(())
}
