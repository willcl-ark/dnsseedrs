use crate::asmap::interpret;
use crate::common::{is_good, BindProtocol, Host, NodeInfo};
use crate::db::{node_info_from_row, open_db_connection, NODE_SELECT_COLUMNS};
use crate::dnssec::{parse_dns_keys_dir, DnsSigningKey, RecordsToSign};

use std::{
    collections::{HashMap, HashSet},
    io::BufReader as StdBufReader,
    net::IpAddr,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    str::FromStr,
    sync::{Arc, RwLock},
    time,
};

use bitcoin::{
    consensus::{Decodable, Encodable},
    network::Network,
    p2p::{
        address::Address,
        message::{NetworkMessage, RawNetworkMessage, MAX_MSG_SIZE},
        message_network::VersionMessage,
        Magic, ServiceFlags,
    },
};
use domain::{
    base::{
        iana::{rcode::Rcode, rtype::Rtype, Class, SecAlg},
        message::Message,
        message_builder::MessageBuilder,
        name::{Name, ParsedName, RelativeName, ToName},
        record::{Record, Ttl},
        serial::Serial,
        CanonicalOrd, Question,
    },
    rdata::{
        aaaa::Aaaa,
        dnssec::{Nsec, RtypeBitmap, RtypeBitmapBuilder},
        rfc1035::{Ns, Soa, A},
    },
    sign::{key::SigningKey, records::FamilyName},
};
use log::{debug, info};
use rand::{
    seq::{index::sample, SliceRandom},
    thread_rng, Rng,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, BufReader, BufWriter},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::Semaphore,
    task::JoinSet,
    time::{interval, timeout},
};

const IPV4_NET_GROUP_MASK: Ipv4Addr = Ipv4Addr::from_octets([0xff, 0xff, 0, 0]);
const IPV6_NET_GROUP_MASK: Ipv6Addr = Ipv6Addr::from_segments([0xffff, 0xffff, 0, 0, 0, 0, 0, 0]);
const IPV6_HE_NET_GROUP_MASK: Ipv6Addr =
    Ipv6Addr::from_segments([0xffff, 0xffff, 0xf000, 0, 0, 0, 0, 0]);
const MAX_DNS_RESULTS: usize = 20;
const DNS_CACHE_VERIFY_CONCURRENCY: usize = 40;
const DNS_CACHE_PROBE_TIMEOUT: time::Duration = time::Duration::from_secs(5);
const UDP_HANDLER_CONCURRENCY: usize = 1024;
const TCP_HANDLER_CONCURRENCY: usize = 256;

#[derive(Clone)]
struct CachedAddrs {
    ipv4: Vec<Ipv4Addr>,
    ipv6: Vec<Ipv6Addr>,
}

impl CachedAddrs {
    fn new() -> CachedAddrs {
        CachedAddrs {
            ipv4: vec![],
            ipv6: vec![],
        }
    }
}

#[derive(Clone, Copy, Default)]
struct CacheTargets {
    ipv4: usize,
    ipv6: usize,
}

fn sample_cached_addrs<T: Copy>(addrs: &[T], limit: usize, rng: &mut impl Rng) -> Vec<T> {
    // Answers are always chosen from the server-maintained cache. The client can choose
    // the record type and service-bit filter via the qname, but it cannot inject or
    // bias specific addresses into the response path.
    if addrs.len() <= limit {
        let mut all = addrs.to_vec();
        all.shuffle(rng);
        return all;
    }

    sample(rng, addrs.len(), limit)
        .into_iter()
        .map(|i| addrs[i])
        .collect()
}

fn ipv4_diversity_key(addr: Ipv4Addr, asmap: Option<&[bool]>) -> u128 {
    if let Some(asmap_data) = asmap {
        let ip_bits = ipv4_mapped_asmap_bits(addr);
        return u128::from(interpret(asmap_data, &ip_bits));
    }

    u128::from(u32::from(addr & IPV4_NET_GROUP_MASK))
}

fn ipv6_diversity_key(addr: Ipv6Addr, asmap: Option<&[bool]>) -> u128 {
    if let Some(asmap_data) = asmap {
        let ip_bits = ipv6_asmap_bits(addr);
        return u128::from(interpret(asmap_data, &ip_bits));
    }

    let group: Ipv6Addr = if addr.octets()[0] == 0x20
        && addr.octets()[1] == 0x01
        && addr.octets()[2] == 0x04
        && addr.octets()[3] == 0x70
    {
        addr & IPV6_HE_NET_GROUP_MASK
    } else {
        addr & IPV6_NET_GROUP_MASK
    };
    u128::from_be_bytes(group.octets())
}

fn add_verified_node_to_cache(
    node: &NodeInfo,
    filters: &[ServiceFlags],
    cache: &mut HashMap<ServiceFlags, CachedAddrs>,
    ipv4_keys: &mut HashMap<ServiceFlags, HashSet<u128>>,
    ipv6_keys: &mut HashMap<ServiceFlags, HashSet<u128>>,
    asmap: Option<&[bool]>,
) {
    let services = ServiceFlags::from(node.services);
    for filter in filters {
        if !services.has(*filter) {
            continue;
        }
        let Some(addrs) = cache.get_mut(filter) else {
            continue;
        };
        match node.addr.host {
            Host::Ipv4(ip) if addrs.ipv4.len() < MAX_DNS_RESULTS => {
                let key = ipv4_diversity_key(ip, asmap);
                if ipv4_keys.entry(*filter).or_default().insert(key) {
                    addrs.ipv4.push(ip);
                }
            }
            Host::Ipv6(ip) if addrs.ipv6.len() < MAX_DNS_RESULTS => {
                let key = ipv6_diversity_key(ip, asmap);
                if ipv6_keys.entry(*filter).or_default().insert(key) {
                    addrs.ipv6.push(ip);
                }
            }
            _ => (),
        }
    }
}

fn cache_targets(
    candidates: &[NodeInfo],
    filters: &[ServiceFlags],
    asmap: Option<&[bool]>,
) -> HashMap<ServiceFlags, CacheTargets> {
    let mut ipv4_keys = HashMap::<ServiceFlags, HashSet<u128>>::new();
    let mut ipv6_keys = HashMap::<ServiceFlags, HashSet<u128>>::new();

    for node in candidates {
        let services = ServiceFlags::from(node.services);
        for filter in filters {
            if !services.has(*filter) {
                continue;
            }
            match node.addr.host {
                Host::Ipv4(ip) => {
                    ipv4_keys
                        .entry(*filter)
                        .or_default()
                        .insert(ipv4_diversity_key(ip, asmap));
                }
                Host::Ipv6(ip) => {
                    ipv6_keys
                        .entry(*filter)
                        .or_default()
                        .insert(ipv6_diversity_key(ip, asmap));
                }
                _ => (),
            }
        }
    }

    filters
        .iter()
        .map(|filter| {
            let ipv4 = ipv4_keys
                .get(filter)
                .map_or(0, |keys| keys.len().min(MAX_DNS_RESULTS));
            let ipv6 = ipv6_keys
                .get(filter)
                .map_or(0, |keys| keys.len().min(MAX_DNS_RESULTS));
            (*filter, CacheTargets { ipv4, ipv6 })
        })
        .collect()
}

fn cache_has_targets(
    cache: &HashMap<ServiceFlags, CachedAddrs>,
    targets: &HashMap<ServiceFlags, CacheTargets>,
) -> bool {
    targets.iter().all(|(filter, target)| {
        let Some(addrs) = cache.get(filter) else {
            return target.ipv4 == 0 && target.ipv6 == 0;
        };
        addrs.ipv4.len() >= target.ipv4 && addrs.ipv6.len() >= target.ipv6
    })
}

async fn probe_bitcoin_v1_version(
    stream: &mut TcpStream,
    node: &NodeInfo,
    chain: Network,
) -> Result<(), std::io::Error> {
    let addr_them = match node.addr.host {
        Host::Ipv4(ip) => Address {
            services: ServiceFlags::NONE,
            address: ip.to_ipv6_mapped().segments(),
            port: node.addr.port,
        },
        Host::Ipv6(ip) => Address {
            services: ServiceFlags::NONE,
            address: ip.segments(),
            port: node.addr.port,
        },
        _ => return Err(std::io::Error::other("unsupported DNS cache probe host")),
    };
    let addr_me = Address {
        services: ServiceFlags::NONE,
        address: [0, 0, 0, 0, 0, 0, 0, 0],
        port: 0,
    };
    let ver_msg = VersionMessage {
        version: 70016,
        services: ServiceFlags::NONE,
        timestamp: i64::try_from(
            time::SystemTime::now()
                .duration_since(time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        )
        .unwrap(),
        receiver: addr_them,
        sender: addr_me,
        nonce: 0,
        user_agent: "/dnsseedrs:0.2.0/".to_string(),
        start_height: -1,
        relay: false,
    };

    let net_magic = chain.magic();
    let mut write_buf = Vec::<u8>::new();
    RawNetworkMessage::new(net_magic, NetworkMessage::Version(ver_msg))
        .consensus_encode(&mut write_buf)?;
    stream.write_all(&write_buf).await?;
    stream.flush().await?;

    let mut reader = BufReader::new(stream);
    loop {
        let mut msg = vec![0_u8; 4];
        reader.read_exact(msg.as_mut_slice()).await?;
        while msg.as_slice() != <Magic as AsRef<[u8]>>::as_ref(&net_magic) {
            msg.drain(0..1);
            let mut next_byte = [0_u8; 1];
            reader.read_exact(&mut next_byte).await?;
            msg.extend(next_byte);
        }

        let mut cmd = [0_u8; 12];
        reader.read_exact(&mut cmd).await?;
        msg.extend(cmd);

        let mut len_bytes = [0_u8; 4];
        reader.read_exact(&mut len_bytes).await?;
        let data_len = u32::from_le_bytes(len_bytes);
        msg.extend(len_bytes);
        if data_len as usize > MAX_MSG_SIZE {
            return Err(std::io::Error::other("message exceeds max length"));
        }

        let mut data = vec![0; data_len as usize];
        reader.read_exact(data.as_mut_slice()).await?;
        msg.extend(data);

        let mut checksum = [0_u8; 4];
        reader.read_exact(&mut checksum).await?;
        msg.extend(checksum);

        let mut msg_reader = StdBufReader::new(msg.as_slice());
        let msg = RawNetworkMessage::consensus_decode(&mut msg_reader)
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        if let NetworkMessage::Version(_) = msg.payload() {
            return Ok(());
        }
    }
}

async fn probe_dns_cache_candidate(node: NodeInfo, chain: Network) -> Option<NodeInfo> {
    let socket_addr = match node.addr.host {
        Host::Ipv4(ip) => SocketAddr::new(IpAddr::V4(ip), node.addr.port),
        Host::Ipv6(ip) => SocketAddr::new(IpAddr::V6(ip), node.addr.port),
        _ => return None,
    };

    let mut stream = match timeout(DNS_CACHE_PROBE_TIMEOUT, TcpStream::connect(socket_addr)).await {
        Ok(Ok(stream)) => stream,
        _ => return None,
    };
    match timeout(
        DNS_CACHE_PROBE_TIMEOUT,
        probe_bitcoin_v1_version(&mut stream, &node, chain),
    )
    .await
    {
        Ok(Ok(())) => Some(node),
        _ => None,
    }
}

async fn build_verified_cache(
    mut candidates: Vec<NodeInfo>,
    seeder: &SeederInfo,
    asmap: Option<&[bool]>,
) -> (HashMap<ServiceFlags, CachedAddrs>, usize) {
    {
        let mut rng = thread_rng();
        candidates.shuffle(&mut rng);
    }

    let filters = seeder
        .allowed_filters
        .values()
        .copied()
        .collect::<Vec<ServiceFlags>>();
    let targets = cache_targets(&candidates, &filters, asmap);

    let mut new_cache = HashMap::<ServiceFlags, CachedAddrs>::new();
    for filter in &filters {
        new_cache.insert(*filter, CachedAddrs::new());
    }

    if cache_has_targets(&new_cache, &targets) {
        return (new_cache, 0);
    }

    let mut ipv4_keys = HashMap::<ServiceFlags, HashSet<u128>>::new();
    let mut ipv6_keys = HashMap::<ServiceFlags, HashSet<u128>>::new();
    let mut join_set = JoinSet::<Option<NodeInfo>>::new();
    let mut next_candidate = 0_usize;
    let mut verified_nodes = 0_usize;

    while next_candidate < candidates.len()
        && join_set.len() < DNS_CACHE_VERIFY_CONCURRENCY
        && !cache_has_targets(&new_cache, &targets)
    {
        let node = candidates[next_candidate].clone();
        next_candidate += 1;
        let chain = seeder.chain;
        join_set.spawn(async move { probe_dns_cache_candidate(node, chain).await });
    }

    while let Some(result) = join_set.join_next().await {
        if let Ok(Some(node)) = result {
            verified_nodes += 1;
            add_verified_node_to_cache(
                &node,
                &filters,
                &mut new_cache,
                &mut ipv4_keys,
                &mut ipv6_keys,
                asmap,
            );
        }

        while next_candidate < candidates.len()
            && join_set.len() < DNS_CACHE_VERIFY_CONCURRENCY
            && !cache_has_targets(&new_cache, &targets)
        {
            let node = candidates[next_candidate].clone();
            next_candidate += 1;
            let chain = seeder.chain;
            join_set.spawn(async move { probe_dns_cache_candidate(node, chain).await });
        }

        if cache_has_targets(&new_cache, &targets) {
            break;
        }
    }

    (new_cache, verified_nodes)
}

fn write_bits_from_octets(bits: &mut [bool], octets: &[u8]) {
    for (byte_index, byte) in octets.iter().enumerate() {
        for bit in 0..u8::BITS as usize {
            bits[(byte_index * 8) + bit] = ((byte >> (7 - bit)) & 1) == 1;
        }
    }
}

fn ipv4_mapped_asmap_bits(addr: Ipv4Addr) -> [bool; 128] {
    let mut bits = [false; 128];
    bits[80..96].fill(true);
    write_bits_from_octets(&mut bits[96..], &addr.octets());
    bits
}

fn ipv6_asmap_bits(addr: Ipv6Addr) -> [bool; 128] {
    let mut bits = [false; 128];
    write_bits_from_octets(&mut bits, &addr.octets());
    bits
}

struct SeederInfo {
    // Static, setup on init and never changes
    seed_domain: Name<Vec<u8>>,
    seed_apex: FamilyName<Name<Vec<u8>>>,
    server_name: Name<Vec<u8>>,
    dnskeys: HashMap<(u16, SecAlg), DnsSigningKey>,
    names_served: Vec<Name<Vec<u8>>>,
    soa_record: Record<Name<Vec<u8>>, Soa<Name<Vec<u8>>>>,
    chain: Network,

    // Consts, but can't make them compile time.
    allowed_filters: HashMap<String, ServiceFlags>,
    apex_rtypes: RtypeBitmap<Vec<u8>>,
    other_rtypes: RtypeBitmap<Vec<u8>>,
}

impl SeederInfo {
    fn new(
        seed_name: &str,
        server_name: &str,
        soa_rname: &str,
        dnskeys_dir: Option<String>,
        chain: Network,
    ) -> SeederInfo {
        // Parse the name strings
        let seed_domain_dname: Name<Vec<u8>> = Name::from_str(seed_name).unwrap();
        let seed_apex = FamilyName::new(seed_domain_dname.clone(), Class::IN);
        let server_dname: Name<Vec<u8>> = Name::from_str(server_name).unwrap();
        let soa_rname_dname: Name<Vec<u8>> = Name::from_str(soa_rname).unwrap();

        // Fixed table of allowed filters
        let allowed_filters: HashMap<String, ServiceFlags> = HashMap::from([
            ("x1".to_string(), ServiceFlags::NETWORK),
            (
                "x5".to_string(),
                ServiceFlags::NETWORK | ServiceFlags::BLOOM,
            ),
            (
                "x9".to_string(),
                ServiceFlags::NETWORK | ServiceFlags::WITNESS,
            ),
            (
                "x49".to_string(),
                ServiceFlags::NETWORK | ServiceFlags::WITNESS | ServiceFlags::COMPACT_FILTERS,
            ),
            (
                "x809".to_string(),
                ServiceFlags::NETWORK | ServiceFlags::WITNESS | ServiceFlags::P2P_V2,
            ),
            (
                "x849".to_string(),
                ServiceFlags::NETWORK
                    | ServiceFlags::WITNESS
                    | ServiceFlags::P2P_V2
                    | ServiceFlags::COMPACT_FILTERS,
            ),
            (
                "xd".to_string(),
                ServiceFlags::NETWORK | ServiceFlags::WITNESS | ServiceFlags::BLOOM,
            ),
            ("x400".to_string(), ServiceFlags::NETWORK_LIMITED),
            (
                "x404".to_string(),
                ServiceFlags::NETWORK_LIMITED | ServiceFlags::BLOOM,
            ),
            (
                "x408".to_string(),
                ServiceFlags::NETWORK_LIMITED | ServiceFlags::WITNESS,
            ),
            (
                "x448".to_string(),
                ServiceFlags::NETWORK_LIMITED
                    | ServiceFlags::WITNESS
                    | ServiceFlags::COMPACT_FILTERS,
            ),
            (
                "xc08".to_string(),
                ServiceFlags::NETWORK_LIMITED | ServiceFlags::WITNESS | ServiceFlags::P2P_V2,
            ),
            (
                "xc48".to_string(),
                ServiceFlags::NETWORK_LIMITED
                    | ServiceFlags::WITNESS
                    | ServiceFlags::P2P_V2
                    | ServiceFlags::COMPACT_FILTERS,
            ),
            (
                "x40c".to_string(),
                ServiceFlags::NETWORK_LIMITED | ServiceFlags::WITNESS | ServiceFlags::BLOOM,
            ),
        ]);

        // Get vector of served domain names in canonical ordering
        let mut names_served = Vec::<Name<Vec<u8>>>::new();
        names_served.push(seed_domain_dname.clone());
        for n in allowed_filters.keys() {
            let sub_name: RelativeName<Vec<u8>> = RelativeName::from_str(n).unwrap();
            names_served.push(sub_name.chain(seed_domain_dname.clone()).unwrap().to_name());
        }
        names_served.sort_by(|a, b| a.canonical_cmp(b));

        // Build rtype bitmaps
        let mut apex_rtype_builder = RtypeBitmapBuilder::new_vec();
        let _ = apex_rtype_builder.add(Rtype::A);
        let _ = apex_rtype_builder.add(Rtype::AAAA);
        let _ = apex_rtype_builder.add(Rtype::NS);
        let _ = apex_rtype_builder.add(Rtype::SOA);
        let _ = apex_rtype_builder.add(Rtype::RRSIG);
        let _ = apex_rtype_builder.add(Rtype::NSEC);
        let _ = apex_rtype_builder.add(Rtype::DNSKEY);
        let mut other_rtype_builder = RtypeBitmapBuilder::new_vec();
        let _ = other_rtype_builder.add(Rtype::A);
        let _ = other_rtype_builder.add(Rtype::AAAA);
        let _ = other_rtype_builder.add(Rtype::RRSIG);
        let _ = other_rtype_builder.add(Rtype::NSEC);

        // Read the DNSSEC keys
        let dnskeys = parse_dns_keys_dir(dnskeys_dir, seed_name);

        // Make static SOA record
        let soa_record = Record::new(
            seed_domain_dname.clone(),
            Class::IN,
            Ttl::from_secs(900),
            Soa::new(
                seed_domain_dname.clone(),
                soa_rname_dname,
                Serial(1),
                Ttl::from_secs(3600),
                Ttl::from_secs(3600),
                Ttl::from_secs(86400),
                Ttl::from_secs(60),
            ),
        );

        SeederInfo {
            seed_domain: seed_domain_dname,
            seed_apex,
            server_name: server_dname,
            dnskeys,
            names_served,
            soa_record,
            chain,
            allowed_filters,
            apex_rtypes: apex_rtype_builder.finalize(),
            other_rtypes: other_rtype_builder.finalize(),
        }
    }

    fn get_soa(&self) -> Record<Name<Vec<u8>>, Soa<Name<Vec<u8>>>> {
        self.soa_record.clone()
    }
}

async fn build_dns_failed(
    req: &Message<[u8]>,
    code: Rcode,
    query: &Option<Question<ParsedName<&[u8]>>>,
    seeder: Arc<SeederInfo>,
) -> Result<Message<Vec<u8>>, String> {
    let res_builder = MessageBuilder::new_vec();
    match res_builder.start_answer(req, code) {
        Ok(res) => {
            // No answer, skip directly to authority
            let mut auth = res.authority();

            // Add SOA record for only NOERROR and NXDOMAIN
            if query.is_some() && (code == Rcode::NOERROR || code == Rcode::NXDOMAIN) {
                auth.header_mut().set_aa(true);
                let mut auth_recs_sign = RecordsToSign::new();
                auth.push(seeder.get_soa()).unwrap();
                auth_recs_sign.add_soa(seeder.get_soa());

                // DNSSEC signing and NSEC records
                if req.opt().is_some()
                    && req.opt().unwrap().dnssec_ok()
                    && !seeder.dnskeys.is_empty()
                {
                    // Set NSEC records
                    let mut next_name;
                    let mut insert_apex = false;
                    match seeder
                        .names_served
                        .binary_search_by(|a| a.canonical_cmp(&query.unwrap().qname()))
                    {
                        Ok(p) => {
                            next_name = p + 1;
                        }
                        Err(p) => {
                            next_name = p;
                            // Insert apex if there is no exact match
                            insert_apex = true
                        }
                    };
                    // Insert NSEC for apex
                    if insert_apex || next_name == 1 {
                        let rec = Record::new(
                            seeder.names_served[0].clone(),
                            Class::IN,
                            Ttl::from_secs(60),
                            Nsec::new(seeder.names_served[1].clone(), seeder.apex_rtypes.clone()),
                        );
                        auth.push(rec.clone()).unwrap();
                        auth_recs_sign.add_nsec(rec);
                    }
                    if next_name > 1 {
                        let prev_name = next_name - 1;
                        // When next_name is out of range, it wraps around
                        if next_name >= seeder.names_served.len() {
                            next_name = 0;
                        }
                        let rec = Record::new(
                            seeder.names_served[prev_name].clone(),
                            Class::IN,
                            Ttl::from_secs(60),
                            Nsec::new(
                                seeder.names_served[next_name].clone(),
                                seeder.other_rtypes.clone(),
                            ),
                        );
                        auth.push(rec.clone()).unwrap();
                        auth_recs_sign.add_nsec(rec);
                    }

                    // Sign
                    for rrsig in auth_recs_sign.sign(&seeder.dnskeys, &seeder.seed_apex) {
                        let _ = auth.push(rrsig);
                    }
                }
            }

            // Additional section
            let mut addl = auth.additional();
            if req.opt().is_some() {
                addl.opt(|opt| {
                    opt.set_rcode(code.into());
                    if req.opt().unwrap().dnssec_ok() {
                        opt.set_dnssec_ok(true);
                    }
                    Ok(())
                })
                .unwrap();
            }

            Ok(addl.into_message())
        }
        Err(e) => Err(format!("Failed to build DNS no data: {e}")),
    }
}

async fn process_dns_request(
    buf: &[u8],
    req_len: usize,
    seeder: Arc<SeederInfo>,
    cache: Arc<RwLock<HashMap<ServiceFlags, CachedAddrs>>>,
) -> Result<Vec<Message<Vec<u8>>>, String> {
    let mut ret_msgs = Vec::<Message<Vec<u8>>>::new();
    let req = match Message::from_slice(&buf[..req_len]) {
        Ok(r) => r,
        Err(e) => {
            return Err(format!("E1 {e}"));
        }
    };

    let req_header = req.header();
    if req_header.qr() {
        // Ignore non-queries
        return Err("Ignored non-query".to_string());
    }
    if req_header.tc() {
        if let Ok(msg) = build_dns_failed(req, Rcode::SERVFAIL, &None, seeder.clone()).await {
            ret_msgs.push(msg)
        }
        return Ok(ret_msgs);
    }

    // Track records for signing
    let mut ans_recs_sign = RecordsToSign::new();

    // Answer the questions
    let mut res_builder = MessageBuilder::new_vec();
    res_builder.header_mut().set_aa(true);
    let mut res = match res_builder.start_answer(req, Rcode::NOERROR) {
        Ok(r) => r,
        Err(e) => {
            return Err(format!("E3 {e}"));
        }
    };
    for q_r in req.question() {
        let question = match q_r {
            Ok(q) => q,
            Err(..) => {
                if let Ok(msg) = build_dns_failed(req, Rcode::FORMERR, &None, seeder.clone()).await
                {
                    ret_msgs.push(msg);
                }
                continue;
            }
        };
        let name = question.qname();

        // Make sure we can serve this
        if !name.ends_with(&seeder.seed_domain) {
            if let Ok(msg) =
                build_dns_failed(req, Rcode::REFUSED, &Some(question), seeder.clone()).await
            {
                ret_msgs.push(msg);
            }
            continue;
        }

        // Check for xNNN.<name> service flag filter
        let mut filter: ServiceFlags = ServiceFlags::NETWORK | ServiceFlags::WITNESS;
        if name.label_count() != seeder.seed_domain.label_count() {
            if name.label_count() != seeder.seed_domain.label_count() + 1 {
                if let Ok(msg) =
                    build_dns_failed(req, Rcode::NXDOMAIN, &Some(question), seeder.clone()).await
                {
                    ret_msgs.push(msg);
                }
                continue;
            }
            let filter_label = name.first().to_string();
            let this_filter = seeder.allowed_filters.get(&filter_label);
            if this_filter.is_none() {
                if let Ok(msg) =
                    build_dns_failed(req, Rcode::NXDOMAIN, &Some(question), seeder.clone()).await
                {
                    ret_msgs.push(msg);
                }
                continue;
            }
            filter = *this_filter.unwrap();
        }

        // Check supported class
        match question.qclass() {
            Class::IN => (),
            _ => {
                if let Ok(msg) =
                    build_dns_failed(req, Rcode::NOTIMP, &Some(question), seeder.clone()).await
                {
                    ret_msgs.push(msg);
                }
                continue;
            }
        };

        // Only return these for the apex domain
        if name.eq(&seeder.seed_domain) {
            // Handle SOA separately
            if question.qtype() == Rtype::SOA {
                res.push(seeder.get_soa()).unwrap();
                ans_recs_sign.add_soa(seeder.get_soa());
                continue;
            };

            // Handle NS separately
            if question.qtype() == Rtype::NS {
                let rec = Record::new(
                    name.to_name::<Vec<u8>>(),
                    Class::IN,
                    Ttl::from_secs(86400),
                    Ns::new(seeder.server_name.clone()),
                );
                res.push(rec.clone()).unwrap();
                ans_recs_sign.add_ns(rec);
                continue;
            };

            // Handle DNSKEY separately
            if question.qtype() == Rtype::DNSKEY {
                for dnskey in seeder.dnskeys.values() {
                    let rec = Record::new(
                        name.to_name::<Vec<u8>>(),
                        Class::IN,
                        Ttl::from_secs(3600),
                        dnskey.dnskey().unwrap(),
                    );
                    let _ = res.push(rec.clone());
                    ans_recs_sign.add_dnskey(rec);
                }
                continue;
            }
        }

        // Check supported record type
        match question.qtype() {
            Rtype::A => (),
            Rtype::AAAA => (),
            _ => {
                if let Ok(msg) =
                    build_dns_failed(req, Rcode::NOERROR, &Some(question), seeder.clone()).await
                {
                    ret_msgs.push(msg);
                }
                continue;
            }
        };

        let mut rng = thread_rng();

        match question.qtype() {
            Rtype::A => {
                let selected = {
                    let cache_read = cache.read().unwrap();
                    let Some(read_addrs) = cache_read.get(&filter) else {
                        continue;
                    };
                    // Sample at most 20 server-side cached answers for this filter. This keeps
                    // per-request work bounded without changing the trust model: the response is
                    // still derived solely from cached nodes the crawler admitted earlier.
                    sample_cached_addrs(&read_addrs.ipv4, MAX_DNS_RESULTS, &mut rng)
                };
                for node in selected {
                    let rec = Record::new(
                        name.to_name::<Vec<u8>>(),
                        Class::IN,
                        Ttl::from_secs(60),
                        A::new(node),
                    );
                    res.push(rec.clone()).unwrap();
                    ans_recs_sign.add_a(rec);
                }
            }
            Rtype::AAAA => {
                let selected = {
                    let cache_read = cache.read().unwrap();
                    let Some(read_addrs) = cache_read.get(&filter) else {
                        continue;
                    };
                    // IPv6 answers follow the same server-side sampling path as IPv4 answers.
                    sample_cached_addrs(&read_addrs.ipv6, MAX_DNS_RESULTS, &mut rng)
                };
                for node in selected {
                    let rec = Record::new(
                        name.to_name::<Vec<u8>>(),
                        Class::IN,
                        Ttl::from_secs(60),
                        Aaaa::new(node),
                    );
                    res.push(rec.clone()).unwrap();
                    ans_recs_sign.add_aaaa(rec);
                }
            }
            _ => {
                continue;
            }
        };
    }

    // Insert RRSIG if DNSSEC
    if req.opt().is_some()
        && req.opt().unwrap().dnssec_ok()
        && res.counts().ancount() > 0
        && !seeder.dnskeys.is_empty()
    {
        // Sign exactly the records selected above. Sampling changes which cached answers are
        // returned, but when DNSSEC is enabled the final answer set is still authenticated as a
        // unit before we send it.
        for rrsig in ans_recs_sign.sign(&seeder.dnskeys, &seeder.seed_apex) {
            let _ = res.push(rrsig);
        }
    }

    // Advance to authority section
    let mut auth = res.authority();

    // Add SOA to authority section if there are no answers
    if auth.counts().ancount() == 0 {
        let mut auth_recs_sign = RecordsToSign::new();
        auth.push(seeder.get_soa()).unwrap();
        auth_recs_sign.add_soa(seeder.get_soa());

        if req.opt().is_some() && req.opt().unwrap().dnssec_ok() && !seeder.dnskeys.is_empty() {
            // Sign it
            for rrsig in auth_recs_sign.sign(&seeder.dnskeys, &seeder.seed_apex) {
                let _ = auth.push(rrsig);
            }
        }
    }

    // Advance to additional section
    let mut addl = auth.additional();

    // Add OPT to our response if it is there
    if req.opt().is_some() {
        addl.opt(|opt| {
            opt.set_rcode(Rcode::NOERROR.into());
            if req.opt().unwrap().dnssec_ok() {
                opt.set_dnssec_ok(true);
            }
            Ok(())
        })
        .unwrap();
    }

    ret_msgs.push(addl.into_message());
    Ok(ret_msgs)
}

async fn dns_socket_task(
    proto: BindProtocol,
    bind: SocketAddr,
    seeder: Arc<SeederInfo>,
    cache: Arc<RwLock<HashMap<ServiceFlags, CachedAddrs>>>,
) {
    if proto == BindProtocol::Udp {
        // Bind UDP socket
        let udp_sock = Arc::new(UdpSocket::bind(bind).await.unwrap());
        // Bound the number of in-flight UDP handlers so a burst of queries cannot create
        // unbounded task fanout and starve the runtime.
        let handler_sem = Arc::new(Semaphore::new(UDP_HANDLER_CONCURRENCY));
        info!("Bound UDP socket {}", udp_sock.local_addr().unwrap());

        // Main loop
        loop {
            let mut buf = [0_u8; 1500];
            let (req_len, from) = udp_sock.recv_from(&mut buf).await.unwrap();

            let udp_sock_clone = udp_sock.clone();
            let seeder_clone = seeder.clone();
            let cache_clone = cache.clone();
            let handler_permit = handler_sem.clone().acquire_owned().await.unwrap();
            tokio::spawn(async move {
                let _handler_permit = handler_permit;
                match process_dns_request(&buf, req_len, seeder_clone.clone(), cache_clone.clone())
                    .await
                {
                    Ok(msgs) => {
                        // Send each message individually
                        for msg in msgs {
                            let _ = udp_sock_clone.send_to(msg.as_slice(), from).await;
                        }
                    }
                    Err(e) => debug!("{e}"),
                }
            });
        }
    } else if proto == BindProtocol::Tcp {
        // Bind TCP Socket
        let tcp_sock = TcpListener::bind(bind).await.unwrap();
        // TCP sessions stay open longer than a single UDP exchange, so keep a separate cap
        // here to limit concurrent connection handlers.
        let handler_sem = Arc::new(Semaphore::new(TCP_HANDLER_CONCURRENCY));
        info!("Bound TCP socket {}", tcp_sock.local_addr().unwrap());

        // Main loop
        loop {
            let (mut tcp_stream, _from) = tcp_sock.accept().await.unwrap();

            let seeder_clone = seeder.clone();
            let cache_clone = cache.clone();
            let handler_permit = handler_sem.clone().acquire_owned().await.unwrap();
            tokio::spawn(async move {
                let _handler_permit = handler_permit;
                let (mut read_sock, mut write_sock) = tcp_stream.split();
                let mut reader = BufReader::new(&mut read_sock);
                let mut writer = BufWriter::new(&mut write_sock);

                // Loop to handle all possible requests
                loop {
                    // If we either get EOF, or it's been 2 minutes without data, exit
                    let req_len;
                    match timeout(time::Duration::from_secs(120), reader.read_u16()).await {
                        Ok(rb) => match rb {
                            Ok(r) => req_len = r,
                            Err(_) => break,
                        },
                        Err(_) => break,
                    }
                    let mut req = vec![0_u8; req_len as usize];
                    reader.read_exact(&mut req).await.unwrap();

                    match process_dns_request(
                        req.as_slice(),
                        req_len.into(),
                        seeder_clone.clone(),
                        cache_clone.clone(),
                    )
                    .await
                    {
                        Ok(msgs) => {
                            // Send each message individually
                            for msg in msgs {
                                writer
                                    .write_u16(msg.as_octets().len() as u16)
                                    .await
                                    .unwrap();
                                writer.write_all(msg.as_slice()).await.unwrap();
                            }
                            writer.flush().await.unwrap();
                        }
                        Err(e) => debug!("{e}"),
                    }
                }
            });
        }
    }
}

async fn fill_cache(
    cache: Arc<RwLock<HashMap<ServiceFlags, CachedAddrs>>>,
    seeder: Arc<SeederInfo>,
    db_conn: rusqlite::Connection,
    asmap: Option<Vec<bool>>,
) {
    let mut interval = interval(time::Duration::from_secs(600));
    loop {
        // Do ever 10 minutes (first time will happen immediately)
        interval.tick().await;

        let refill_start = time::Instant::now();
        info!("Starting DNS cache refill from db");

        let mut scanned_nodes = 0_usize;
        let candidates = {
            let mut candidates = Vec::<NodeInfo>::new();
            let mut select_nodes = db_conn
                .prepare(&format!(
                    "SELECT {NODE_SELECT_COLUMNS} FROM nodes WHERE try_count > 0"
                ))
                .unwrap();
            let node_iter = select_nodes.query_map([], node_info_from_row).unwrap();

            for node_res in node_iter {
                scanned_nodes += 1;
                let Ok(Some(node)) = node_res else {
                    continue;
                };
                if !is_good(&node, &seeder.chain) {
                    continue;
                }
                match node.addr.host {
                    Host::Ipv4(..) | Host::Ipv6(..) => candidates.push(node),
                    _ => (),
                }
            }
            candidates
        };

        let candidate_nodes = candidates.len();
        let (new_cache, verified_nodes) =
            build_verified_cache(candidates, &seeder, asmap.as_deref()).await;

        {
            let mut cache_write = cache.write().unwrap();
            for (filter, new_addrs) in new_cache {
                cache_write.insert(filter, new_addrs);
            }
        }
        let cached_addrs = {
            let cache_read = cache.read().unwrap();
            cache_read
                .values()
                .map(|addrs| addrs.ipv4.len() + addrs.ipv6.len())
                .sum::<usize>()
        };
        info!(
            "Finished DNS cache refill from db in {:?}: scanned_nodes={}, candidate_nodes={}, verified_nodes={}, cached_addrs={}",
            refill_start.elapsed(),
            scanned_nodes,
            candidate_nodes,
            verified_nodes,
            cached_addrs
        );
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn dns_thread(
    db_file: &str,
    mut binds: Vec<(BindProtocol, SocketAddr)>,
    seed_domain: &str,
    server_name: &str,
    soa_rname: &str,
    chain: &Network,
    dnssec_keys: Option<String>,
    asmap: Option<Vec<bool>>,
) {
    #[allow(clippy::single_char_pattern)]
    let cache = Arc::new(RwLock::new(HashMap::<ServiceFlags, CachedAddrs>::new()));

    // Setup seeder info
    let seeder = Arc::new(SeederInfo::new(
        seed_domain,
        server_name,
        soa_rname,
        dnssec_keys,
        *chain,
    ));

    let cache_c = cache.clone();
    let seeder_c = seeder.clone();
    let db_conn = open_db_connection(db_file);
    tokio::spawn(async move {
        fill_cache(cache_c, seeder_c, db_conn, asmap).await;
    });

    while binds.len() > 1 {
        // Start a task for each socket
        let (proto, bind) = binds.pop().unwrap();
        let seeder_clone = seeder.clone();
        let cache_clone = cache.clone();
        tokio::spawn(async move {
            dns_socket_task(proto, bind, seeder_clone, cache_clone).await;
        });
    }

    // Use this task for the last bind
    let (proto, bind) = binds.pop().unwrap();
    dns_socket_task(proto, bind, seeder, cache).await;
}

#[cfg(test)]
mod tests {
    use super::{
        add_verified_node_to_cache, cache_targets, ipv4_mapped_asmap_bits, ipv6_asmap_bits,
        sample_cached_addrs, CachedAddrs, MAX_DNS_RESULTS,
    };
    use crate::common::NodeInfo;
    use bitcoin::p2p::ServiceFlags;
    use rand::{rngs::StdRng, SeedableRng};
    use std::{
        collections::{HashMap, HashSet},
        net::{Ipv4Addr, Ipv6Addr},
    };

    fn node_info(address: String, services: ServiceFlags) -> NodeInfo {
        NodeInfo::construct(
            address,
            0,
            0,
            "".to_string(),
            services.to_u64(),
            880000,
            70016,
            10,
            1.0,
            1.0,
            1.0,
            1.0,
            1.0,
        )
        .unwrap()
    }

    #[test]
    fn sample_cached_addrs_returns_all_items_when_under_limit() {
        let mut rng = StdRng::seed_from_u64(1);
        let mut sampled = sample_cached_addrs(&[1_u8, 2, 3], 20, &mut rng);
        sampled.sort_unstable();
        assert_eq!(sampled, vec![1, 2, 3]);
    }

    #[test]
    fn sample_cached_addrs_returns_unique_subset() {
        let mut rng = StdRng::seed_from_u64(7);
        let sampled = sample_cached_addrs(&(0_u8..100).collect::<Vec<_>>(), 20, &mut rng);
        assert_eq!(sampled.len(), 20);
        let unique = sampled.iter().copied().collect::<HashSet<_>>();
        assert_eq!(unique.len(), 20);
        assert!(sampled.iter().all(|v| *v < 100));
    }

    #[test]
    fn ipv4_mapped_asmap_bits_use_ipv4_mapped_prefix() {
        let bits = ipv4_mapped_asmap_bits(Ipv4Addr::new(1, 2, 3, 4));
        assert!(bits[..80].iter().all(|bit| !*bit));
        assert!(bits[80..96].iter().all(|bit| *bit));
        assert_eq!(
            &bits[96..128],
            &[
                false, false, false, false, false, false, false, true, false, false, false, false,
                false, false, true, false, false, false, false, false, false, false, true, true,
                false, false, false, false, false, true, false, false,
            ]
        );
    }

    #[test]
    fn ipv6_asmap_bits_follow_network_bit_order() {
        let bits = ipv6_asmap_bits(Ipv6Addr::new(0x8000, 0, 0, 0, 0, 0, 0, 1));
        assert!(bits[0]);
        assert!(bits[1..127].iter().all(|bit| !*bit));
        assert!(bits[127]);
    }

    #[test]
    fn cache_targets_cap_each_family_at_dns_result_limit() {
        let filter = ServiceFlags::NETWORK | ServiceFlags::WITNESS;
        let filters = vec![filter];
        let candidates = (101..=125)
            .map(|octet| node_info(format!("{octet}.1.1.1:8333"), filter))
            .collect::<Vec<_>>();

        let targets = cache_targets(&candidates, &filters, None);

        assert_eq!(targets.get(&filter).unwrap().ipv4, MAX_DNS_RESULTS);
        assert_eq!(targets.get(&filter).unwrap().ipv6, 0);
    }

    #[test]
    fn verified_cache_keeps_one_ipv4_per_16_without_asmap() {
        let filter = ServiceFlags::NETWORK | ServiceFlags::WITNESS;
        let filters = vec![filter];
        let mut cache = HashMap::from([(filter, CachedAddrs::new())]);
        let mut ipv4_keys = HashMap::new();
        let mut ipv6_keys = HashMap::new();

        for address in ["1.2.3.4:8333", "1.2.4.5:8333"] {
            let node = node_info(address.to_string(), filter);
            add_verified_node_to_cache(
                &node,
                &filters,
                &mut cache,
                &mut ipv4_keys,
                &mut ipv6_keys,
                None,
            );
        }

        assert_eq!(cache.get(&filter).unwrap().ipv4.len(), 1);
    }
}
