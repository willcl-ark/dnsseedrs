mod asmap;
mod common;
mod crawl;
mod db;
mod dns;
mod dnssec;
mod dump;

use crate::{
    asmap::decode_asmap,
    common::{BindProtocol, NetStatus},
    crawl::crawler_thread,
    db::{initialize_database, open_db_connection},
    dns::dns_thread,
    dump::dumper_thread,
};

use std::{
    collections::HashSet,
    net::SocketAddr,
    path::Path,
    str::FromStr,
    sync::{Arc, Mutex},
};

use bitcoin::network::Network;
use clap::Parser;

#[derive(Parser)]
#[command(version, about, long_about)]
struct Args {
    #[arg(short, long)]
    seednode: Vec<String>,

    #[arg(long, default_value = "sqlite.db")]
    db_file: String,

    #[arg(long, default_value = "seeds.txt")]
    dump_file: String,

    #[arg(long, default_value_t = false)]
    no_ipv4: bool,

    #[arg(long, default_value_t = false)]
    no_ipv6: bool,

    #[arg(short, long, default_value_t = false)]
    cjdns_reachable: bool,

    #[arg(short, long, default_value = "127.0.0.1:9050")]
    onion_proxy: String,

    #[arg(short, long, default_value = "127.0.0.1:4447")]
    i2p_proxy: String,

    #[arg(short, long, default_value_t = 24)]
    threads: usize,

    /// protocol, IP, and port to bind to for servince DNS requests. Defaults are udp://0.0.0.0:53
    /// and tcp://0.0.0.0:53. Specify multiple times for multiple binds
    #[arg(short, long)]
    bind: Vec<String>,

    #[arg(long, default_value = "main")]
    chain: String,

    /// The path to a directory containing DNSSEC keys produced by dnssec-keygen
    #[arg(long)]
    dnssec_keys: Option<String>,

    /// The path to an asmap file
    #[arg(long)]
    asmap: Option<String>,

    /// The domain name for which this server will return results for
    #[arg()]
    seed_domain: String,

    /// The domain name of this server itself, i.e. what the NS record will point to
    #[arg()]
    server_name: String,

    /// The exact string to place in the rname field of the SOA record
    #[arg()]
    soa_rname: String,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    // Pick the network
    let chain_p = Network::from_core_arg(&args.chain);
    match chain_p {
        Ok(Network::Bitcoin)
        | Ok(Network::Testnet)
        | Ok(Network::Testnet4)
        | Ok(Network::Signet) => (),
        _ => {
            println!("Unsupported network type: {}", args.chain);
            std::process::exit(1);
        }
    }
    let chain = chain_p.unwrap();

    // Check that DNSSEC keys directory is a directory
    if let Some(dnssec_keys) = &args.dnssec_keys {
        if !Path::new(dnssec_keys).is_dir() {
            println!("{} is not a directory", dnssec_keys);
            std::process::exit(1);
        }
    }

    // Open the ASMap file
    let asmap: Option<Vec<bool>>;
    if let Some(asmap_path) = &args.asmap {
        if !Path::new(asmap_path).is_file() {
            println!("{} is not a file", asmap_path);
            std::process::exit(1);
        }
        asmap = Some(decode_asmap(&args.asmap.unwrap()));
    } else {
        asmap = None;
    }

    // Parse the binds
    let mut bindset = HashSet::<(BindProtocol, SocketAddr)>::new();
    for bind in args.bind {
        let proto: BindProtocol;
        if bind.starts_with("udp://") {
            proto = BindProtocol::Udp
        } else if bind.starts_with("tcp://") {
            proto = BindProtocol::Tcp
        } else {
            println!("{bind} is not a valid bind");
            std::process::exit(1);
        }
        let bind_addr = match SocketAddr::from_str(&bind[6..]) {
            Ok(a) => a,
            Err(_) => {
                println!("{bind} is not a valid bind");
                std::process::exit(1);
            }
        };
        bindset.insert((proto, bind_addr));
    }
    if bindset.is_empty() {
        bindset.insert((
            BindProtocol::Udp,
            SocketAddr::from_str("0.0.0.0:53").unwrap(),
        ));
        bindset.insert((
            BindProtocol::Tcp,
            SocketAddr::from_str("0.0.0.0:53").unwrap(),
        ));
    }
    let binds = bindset.iter().cloned().collect();

    let net_status = NetStatus {
        chain,
        ipv4: !args.no_ipv4,
        ipv6: !args.no_ipv6,
        cjdns: args.cjdns_reachable,
        onion_proxy: Some(args.onion_proxy),
        i2p_proxy: Some(args.i2p_proxy),
    };

    let db_file = args.db_file.clone();
    let dump_file = args.dump_file.clone();
    let dump_db_file = db_file.clone();
    let seed_domain = args.seed_domain.clone();
    let server_name = args.server_name.clone();
    let soa_rname = args.soa_rname.clone();
    let dnssec_keys = args.dnssec_keys.clone();
    let db_conn = open_db_connection(&db_file);
    initialize_database(&db_conn, &args.seednode);
    let crawl_db_conn = Arc::new(Mutex::new(db_conn));

    // Start crawler threads
    let db_conn_c = crawl_db_conn.clone();
    let net_status_c: NetStatus = net_status.clone();
    let t_crawl = tokio::spawn(async move {
        crawler_thread(db_conn_c, args.threads - 3, net_status_c).await;
    });

    // Start dumper thread
    let t_dump = tokio::spawn(async move {
        dumper_thread(&dump_db_file, &dump_file, &chain).await;
    });

    // Start DNS thread
    let t_dns = tokio::spawn(async move {
        dns_thread(
            &db_file,
            binds,
            &seed_domain,
            &server_name,
            &soa_rname,
            &chain,
            dnssec_keys,
            asmap,
        )
        .await;
    });

    // Select on task futures as a watchdog to exit if any main thread has died
    tokio::select! {
        r = t_crawl => r.unwrap(),
        r = t_dump => r.unwrap(),
        r = t_dns => r.unwrap(),
    };
}
