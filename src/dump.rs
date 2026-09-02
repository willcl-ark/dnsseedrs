use crate::common::{is_good, NodeInfo};
use crate::db::{node_info_from_row, open_db_connection, NODE_SELECT_COLUMNS};

use std::{
    path::Path,
    time::Instant,
    time::{Duration as StdDuration, SystemTime, UNIX_EPOCH},
};

use async_compression::tokio::write::GzipEncoder;
use bitcoin::network::Network;
use log::{debug, info, warn};
use tokio::fs::{metadata, rename, File};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::time::{sleep, Duration};

const GZIP_ARCHIVE_INTERVAL: StdDuration = StdDuration::from_secs(24 * 60 * 60);

fn archive_date(time: SystemTime) -> String {
    let days = time.duration_since(UNIX_EPOCH).unwrap().as_secs() as i64 / 86_400;
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let month_part = (5 * doy + 2) / 153;
    let day = doy - (153 * month_part + 2) / 5 + 1;
    let month = month_part + if month_part < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}")
}

async fn rotate_gzip_archive(gz_path: &Path) {
    let modified = match metadata(gz_path).await {
        Ok(metadata) => metadata.modified().unwrap(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
        Err(error) => panic!("Failed to stat {}: {error}", gz_path.display()),
    };
    if modified.elapsed().unwrap_or_default() < GZIP_ARCHIVE_INTERVAL {
        return;
    }

    let archive_path = format!("{}.{}", gz_path.display(), archive_date(modified));
    info!("Archiving {} as {}", gz_path.display(), archive_path);
    rename(gz_path, archive_path).await.unwrap();
}

pub async fn dumper_thread(db_file: &str, dump_file: &str, chain: &Network) {
    let db_conn = open_db_connection(db_file);
    let mut count = 0;
    loop {
        // Sleep for 100s, then 200s, 400s, 800s, 1600s, and then 3200s forever
        sleep(Duration::from_secs(100 << count)).await;
        if count < 5 {
            count += 1;
        }

        let load_start = Instant::now();
        debug!("Starting dump db scan for {}", dump_file);
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
        debug!(
            "Finished dump db scan for {} in {:?} with {} nodes",
            dump_file,
            load_start.elapsed(),
            nodes.len()
        );

        let node_count = nodes.len();
        let txt_tmp_path = format!("{dump_file}.tmp");
        let txt_start = Instant::now();
        info!("Starting write of {} with {} nodes", dump_file, node_count);
        let mut txt_tmp_file = File::create(&txt_tmp_path).await.unwrap();
        let header = format!(
            "{:<70}{:<6}{:<12}{:^8}{:^8}{:^8}{:^8}{:^8}{:^9}{:<18}{:<8}user_agent {:<12}{:<10}\n",
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
            "version",
            "last_tried",
            "try_count",
        );
        let _ = txt_tmp_file.write(header.as_bytes()).await.unwrap();
        for node in nodes {
            let line = format!(
                "{:<70}{:<6}{:<12}{:>6.2}% {:>6.2}% {:>6.2}% {:>6.2}% {:>7.2}% {:<8}{:0>16x}  {:<8}\"{}\" {} {}\n",
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
                node.last_tried,
                node.try_count,
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

        rotate_gzip_archive(archive_path).await;
        rename(gz_tmp_path, archive_path).await.unwrap();
        info!(
            "Finished writing {} in {:?}",
            archive_path.display(),
            gz_start.elapsed()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::archive_date;
    use std::time::{Duration, UNIX_EPOCH};

    #[test]
    fn archive_date_formats_utc_date() {
        let time = UNIX_EPOCH + Duration::from_secs(1_735_689_600);
        assert_eq!(archive_date(time), "2025-01-01");
    }
}
