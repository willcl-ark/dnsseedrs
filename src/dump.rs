use crate::common::{is_good, NodeInfo};
use crate::db::{node_info_from_row, open_db_connection, NODE_SELECT_COLUMNS};

use std::{path::Path, time::Instant};

use async_compression::tokio::write::GzipEncoder;
use bitcoin::network::Network;
use log::{info, warn};
use tokio::fs::{rename, File};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::time::{sleep, Duration};

pub async fn dumper_thread(db_file: &str, dump_file: &str, chain: &Network) {
    let db_conn = open_db_connection(db_file);
    let mut count = 0;
    loop {
        // Sleep for 100s, then 200s, 400s, 800s, 1600s, and then 3200s forever
        sleep(Duration::from_secs(100 << count)).await;
        if count < 5 {
            count += 1;
        }

        let nodes: Vec<NodeInfo>;
        {
            let mut select_nodes = db_conn
                .prepare(&format!(
                    "SELECT {NODE_SELECT_COLUMNS} FROM nodes WHERE try_count > 0"
                ))
                .unwrap();
            let node_iter = select_nodes.query_map([], node_info_from_row).unwrap();
            nodes = node_iter
                .filter_map(|n| match n {
                    Ok(ni) => ni,
                    Err(e) => {
                        warn!("{e}");
                        None
                    }
                })
                .collect();
        }

        let node_count = nodes.len();
        let txt_tmp_path = format!("{dump_file}.tmp");
        let txt_start = Instant::now();
        info!("Starting write of {} with {} nodes", dump_file, node_count);
        let mut txt_tmp_file = File::create(&txt_tmp_path).await.unwrap();
        let header = format!(
            "{:<70}{:<6}{:<12}{:^8}{:^8}{:^8}{:^8}{:^8}{:^9}{:<18}{:<8}user_agent\n",
            "# address",
            "good",
            "last_seen",
            "%(2h)",
            "%(8h)",
            "%(1d)",
            "%(1w)",
            "%(1m)",
            "blocks",
            "services",
            "version"
        );
        let _ = txt_tmp_file.write(header.as_bytes()).await.unwrap();
        for node in nodes {
            let line = format!(
                "{:<70}{:<6}{:<12}{:>6.2}% {:>6.2}% {:>6.2}% {:>6.2}% {:>7.2}% {:<8}{:0>16x}  {:<8}\"{}\"\n",
                node.addr.to_string(),
                i32::from(is_good(&node, chain)),
                node.last_seen,
                node.reliability_2h * 100.0,
                node.reliability_8h * 100.0,
                node.reliability_1d * 100.0,
                node.reliability_1w * 100.0,
                node.reliability_1m * 100.0,
                node.starting_height,
                node.services,
                node.protocol_version,
                node.user_agent,
            );
            let _ = txt_tmp_file.write(line.as_bytes()).await.unwrap();
        }
        txt_tmp_file.flush().await.unwrap();
        rename(txt_tmp_path.clone(), dump_file).await.unwrap();
        info!(
            "Finished writing {} in {:?} with {} nodes",
            dump_file,
            txt_start.elapsed(),
            node_count
        );

        // Compress with gz
        let gz_tmp_path = format!("{dump_file}.gz.tmp");
        let gz_path = format!("{dump_file}.gz");
        let archive_path = Path::new(&gz_path);
        let gz_start = Instant::now();
        info!("Starting write of {}", archive_path.display());
        let gz_tmp_file = File::create(&gz_tmp_path).await.unwrap();
        let mut enc = GzipEncoder::new(gz_tmp_file);
        let f = File::open(dump_file).await.unwrap();
        let mut reader = BufReader::new(f);

        let mut buffer = [0; 1024 * 256];
        loop {
            match reader.read(&mut buffer).await {
                Ok(0) => break, // EOF
                Ok(count) => enc.write_all(&buffer[..count]).await.unwrap(),
                Err(e) => panic!("Failed to read from file: {e}"),
            }
        }
        enc.shutdown().await.unwrap();

        rename(gz_tmp_path, archive_path).await.unwrap();
        info!(
            "Finished writing {} in {:?}",
            archive_path.display(),
            gz_start.elapsed()
        );
    }
}
