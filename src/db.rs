use crate::common::{parse_address, NodeInfo, NodeTransport};

use std::time::Duration;

use log::warn;
use rusqlite::{params, Connection};

const SQLITE_BUSY_TIMEOUT: Duration = Duration::from_secs(5);
const CURRENT_DB_VERSION: i32 = 2;

pub const NODE_SELECT_COLUMNS: &str = "address, last_tried, last_seen, user_agent, services, \
    starting_height, protocol_version, try_count, reliability_2h, reliability_8h, \
    reliability_1d, reliability_1w, reliability_1m";

pub fn open_db_connection(path: &str) -> Connection {
    let conn = Connection::open(path).unwrap();
    configure_connection(&conn);
    conn
}

fn configure_connection(conn: &Connection) {
    conn.busy_timeout(SQLITE_BUSY_TIMEOUT).unwrap();
    conn.execute_batch(
        "
        PRAGMA journal_mode = WAL;
        PRAGMA synchronous = NORMAL;
        ",
    )
    .unwrap();
}

pub fn node_info_from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Option<NodeInfo>> {
    let address: String = r.get(0)?;
    Ok(NodeInfo::construct(
        address,
        r.get(1)?,
        r.get(2)?,
        r.get(3)?,
        u64::from_be_bytes(r.get(4)?),
        r.get(5)?,
        r.get(6)?,
        r.get(7)?,
        r.get(8)?,
        r.get(9)?,
        r.get(10)?,
        r.get(11)?,
        r.get(12)?,
    )
    .ok())
}

fn schema_version(conn: &Connection) -> i32 {
    conn.query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap()
}

fn has_transport_column(conn: &Connection) -> bool {
    conn.prepare("PRAGMA table_info('nodes')")
        .unwrap()
        .query_map([], |row| row.get::<usize, String>(1))
        .unwrap()
        .filter_map(Result::ok)
        .any(|name| name == "transport")
}

fn transport_sql_value(address: &str) -> i64 {
    NodeTransport::from_address(address)
        .unwrap_or(NodeTransport::Direct)
        .as_sql()
}

fn backfill_node_transports(conn: &mut Connection) {
    let tx = conn.transaction().unwrap();
    let addresses = {
        let mut select_nodes = tx.prepare("SELECT address FROM nodes").unwrap();
        select_nodes
            .query_map([], |row| row.get::<usize, String>(0))
            .unwrap()
            .filter_map(Result::ok)
            .collect::<Vec<_>>()
    };

    let mut update_transport = tx
        .prepare("UPDATE nodes SET transport = ? WHERE address = ?")
        .unwrap();
    for address in addresses {
        update_transport
            .execute(params![transport_sql_value(&address), address])
            .unwrap();
    }
    drop(update_transport);
    tx.commit().unwrap();
}

pub fn initialize_database(conn: &mut Connection, seednodes: &[String]) {
    conn.execute(
        "CREATE TABLE if NOT EXISTS 'nodes' (
            address TEXT PRIMARY KEY,
            last_tried INTEGER NOT NULL,
            last_seen INTEGER NOT NULL,
            user_agent TEXT NOT NULL,
            services BLOB NOT NULL,
            starting_height INTEGER NOT NULL,
            protocol_version INTEGER NOT NULL,
            try_count INTEGER NOT NULL,
            reliability_2h REAL NOT NULL,
            reliability_8h REAL NOT NULL,
            reliability_1d REAL NOT NULL,
            reliability_1w REAL NOT NULL,
            reliability_1m REAL NOT NULL,
            transport INTEGER NOT NULL DEFAULT 0
        )",
        [],
    )
    .unwrap();

    let mut needs_transport_backfill = schema_version(conn) < CURRENT_DB_VERSION;
    if !has_transport_column(conn) {
        conn.execute(
            "ALTER TABLE nodes ADD COLUMN transport INTEGER NOT NULL DEFAULT 0",
            [],
        )
        .unwrap();
        needs_transport_backfill = true;
    }

    let mut new_node_stmt = conn
        .prepare(
            "INSERT OR IGNORE INTO nodes (
                address, last_tried, last_seen, user_agent, services, starting_height,
                protocol_version, try_count, reliability_2h, reliability_8h,
                reliability_1d, reliability_1w, reliability_1m, transport
            ) VALUES(?, 0, 0, '', ?, 0, 0, 0, 0.0, 0.0, 0.0, 0.0, 0.0, ?)",
        )
        .unwrap();
    for seednode in seednodes {
        new_node_stmt
            .execute(params![
                seednode,
                0_u64.to_be_bytes(),
                transport_sql_value(seednode)
            ])
            .unwrap();
    }
    drop(new_node_stmt);

    let invalid_nodes = {
        let mut select_nodes = conn.prepare("SELECT address FROM nodes").unwrap();
        let node_iter = select_nodes
            .query_map([], |row| Ok(row.get::<usize, String>(0).unwrap()))
            .unwrap();
        node_iter
            .filter_map(|node| {
                let addr = node.ok()?;
                if parse_address(&addr).is_err() {
                    Some(addr)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>()
    };

    let mut del_stmt = conn.prepare("DELETE FROM nodes WHERE address = ?").unwrap();
    for addr in invalid_nodes {
        warn!("Deleting invalid node {}", addr);
        del_stmt.execute(params![addr]).unwrap();
    }
    drop(del_stmt);

    if needs_transport_backfill {
        backfill_node_transports(conn);
    }

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_nodes_last_tried ON nodes(last_tried)",
        [],
    )
    .unwrap();
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_nodes_transport_last_tried_address \
         ON nodes(transport, last_tried, address)",
        [],
    )
    .unwrap();
    conn.execute("DROP INDEX IF EXISTS idx_nodes_last_tried_address", [])
        .unwrap();
    conn.pragma_update(None, "user_version", CURRENT_DB_VERSION)
        .unwrap();
}

#[cfg(test)]
mod tests {
    use super::initialize_database;
    use rusqlite::Connection;

    #[test]
    fn initialize_database_migrates_transport_column_and_indexes() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute(
            "CREATE TABLE nodes (
                address TEXT PRIMARY KEY,
                last_tried INTEGER NOT NULL,
                last_seen INTEGER NOT NULL,
                user_agent TEXT NOT NULL,
                services BLOB NOT NULL,
                starting_height INTEGER NOT NULL,
                protocol_version INTEGER NOT NULL,
                try_count INTEGER NOT NULL,
                reliability_2h REAL NOT NULL,
                reliability_8h REAL NOT NULL,
                reliability_1d REAL NOT NULL,
                reliability_1w REAL NOT NULL,
                reliability_1m REAL NOT NULL
            )",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO nodes VALUES(
                'duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion:8333',
                0, 0, '', x'0000000000000000', 0, 0, 0, 0.0, 0.0, 0.0, 0.0, 0.0
            )",
            [],
        )
        .unwrap();
        conn.execute(
            "CREATE INDEX idx_nodes_last_tried_address ON nodes(last_tried, address)",
            [],
        )
        .unwrap();
        initialize_database(
            &mut conn,
            &["not-an-address".to_string(), "1.1.1.1:8333".to_string()],
        );

        let node_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM nodes", [], |row| row.get(0))
            .unwrap();
        assert_eq!(node_count, 2);

        let transport_column_present = conn
            .prepare("PRAGMA table_info('nodes')")
            .unwrap()
            .query_map([], |row| row.get::<usize, String>(1))
            .unwrap()
            .filter_map(Result::ok)
            .any(|name| name == "transport");
        assert!(transport_column_present);

        let onion_transport: i64 = conn
            .query_row(
                "SELECT transport FROM nodes WHERE address = ?",
                ["duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion:8333"],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(onion_transport, 1);

        let index_names = conn
            .prepare("PRAGMA index_list('nodes')")
            .unwrap()
            .query_map([], |row| row.get::<usize, String>(1))
            .unwrap()
            .filter_map(Result::ok)
            .collect::<Vec<_>>();
        assert!(index_names.contains(&"idx_nodes_last_tried".to_string()));
        assert!(index_names.contains(&"idx_nodes_transport_last_tried_address".to_string()));
        assert!(!index_names.contains(&"idx_nodes_last_tried_address".to_string()));

        let schema_version: i32 = conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(schema_version, 2);
    }
}
