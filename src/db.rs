use crate::common::parse_address;

use std::time::Duration;

use rusqlite::{params, Connection};

const SQLITE_BUSY_TIMEOUT: Duration = Duration::from_secs(5);

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

pub fn initialize_database(conn: &Connection, seednodes: &[String]) {
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
            reliability_1m REAL NOT NULL
        )",
        [],
    )
    .unwrap();
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_nodes_last_tried ON nodes(last_tried)",
        [],
    )
    .unwrap();

    let mut new_node_stmt = conn
        .prepare(
            "INSERT OR IGNORE INTO nodes VALUES(?, 0, 0, '', ?, 0, 0, 0, 0.0, 0.0, 0.0, 0.0, 0.0)",
        )
        .unwrap();
    for seednode in seednodes {
        new_node_stmt
            .execute(params![seednode, 0_u64.to_be_bytes()])
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
        println!("Deleting invalid node {}", addr);
        del_stmt.execute(params![addr]).unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::initialize_database;
    use rusqlite::Connection;

    #[test]
    fn initialize_database_creates_index_and_drops_invalid_seeds() {
        let conn = Connection::open_in_memory().unwrap();
        initialize_database(
            &conn,
            &["not-an-address".to_string(), "1.1.1.1:8333".to_string()],
        );

        let node_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM nodes", [], |row| row.get(0))
            .unwrap();
        assert_eq!(node_count, 1);

        let has_last_tried_index = conn
            .prepare("PRAGMA index_list('nodes')")
            .unwrap()
            .query_map([], |row| row.get::<usize, String>(1))
            .unwrap()
            .filter_map(Result::ok)
            .any(|name| name == "idx_nodes_last_tried");
        assert!(has_last_tried_index);
    }
}
