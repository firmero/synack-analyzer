use std::io::Write;
use std::{collections::HashMap, path::PathBuf};
use std::{env, fs, thread, time::Duration};

use chrono::Local;
use etherparse::{InternetSlice, Ipv4Header, ReadError, SlicedPacket, TcpHeaderSlice, TransportSlice};
use pcap::{Active, Capture, Device, Packet, PacketHeader, Precision, Savefile};

use clap::Parser;
use gethostname::gethostname;
use lazy_static::lazy_static;
use log::{debug, error, info, trace, warn, Level};
use prometheus::{
    histogram_opts, labels, opts, register_histogram, register_int_counter, register_int_counter_vec, register_int_gauge, register_int_gauge_vec,
    Histogram, IntCounter, IntCounterVec, IntGauge, IntGaugeVec,
};
use warp::{Filter, Rejection, Reply};

lazy_static! {
    static ref NODE_NAME: String =  env::var("NODE_NAME").unwrap_or(gethostname().to_string_lossy().into());

    static ref COMMON_LABELS: HashMap<String, String> = labels! {
        "node".to_string() => NODE_NAME.to_owned(),
    };

    static ref PM_FILTERED_PROCESSED_PACKET_COUNT: IntCounter = register_int_counter!(opts!(
        "synack_analyzer_filtered_processed_packet_count",
        "Number of packets which synack analyzer read from libpcap.",
        ).const_labels(COMMON_LABELS.to_owned())).unwrap();
    static ref PM_RST_COUNT: IntCounterVec = register_int_counter_vec!(opts!(
        "synack_analyzer_rst_count",
        "Number of rst.",
        ).const_labels(COMMON_LABELS.to_owned()),
        &["tag"]).unwrap();
    static ref PM_SYN_COUNT: IntCounterVec = register_int_counter_vec!(opts!(
        "synack_analyzer_syn_count",
        "Number of syn.",
        ).const_labels(COMMON_LABELS.to_owned()),
        &["tag"]).unwrap();
    // static ref PM_SYN_RETRANS_COUNT: IntCounterVec = register_int_counter_vec!(opts!(
    //     "synack_analyzer_syn_retrans_count",
    //     "Number of syn retrans.",
    //     ).const_labels(COMMON_LABELS.to_owned()),
    //     &["tag"]).unwrap();
    static ref PM_SYNACK_COUNT: IntCounterVec = register_int_counter_vec!(opts!(
        "synack_analyzer_synack_count",
        "Number of synack.",
        ).const_labels(COMMON_LABELS.to_owned()),
        &["tag"]).unwrap();
    // static ref PM_SYNACK_RETRANS_COUNT: IntCounterVec = register_int_counter_vec!(opts!(
    //     "synack_analyzer_synack_retrans_count",
    //     "Number of synacks retrans.",
    //     ).const_labels(COMMON_LABELS.to_owned()),
    //     &["tag"]).unwrap();
    static ref PM_SYNACK_LONG_RESPONSE_COUNT: IntCounterVec = register_int_counter_vec!(opts!(
        "synack_analyzer_synack_longresponse_count",
        "Number of long syn-synack connections.",
        ).const_labels(COMMON_LABELS.to_owned()),
        &["threashold_ms"]).unwrap();
    static ref PM_SYNACK_ANALYZER_ERRORS: IntCounterVec = register_int_counter_vec!(opts!(
        "synack_analyzer_errors",
        "Number of errors.",
        ).const_labels(COMMON_LABELS.to_owned()),
        &["type"]).unwrap();
    static ref PM_SYNACK_RESPONSE_TIME_MS: Histogram = register_histogram!(histogram_opts!(
        "synack_analyzer_synack_response_time_ms",
        "How long it lasted to get synack for the first syn.",
        vec![32.0, 1000.0, 3000.0, 7000.0, 15000.0],
        COMMON_LABELS.to_owned(),
        )).unwrap();

    static ref PM_STATS_DROPPED_COUNT: IntGauge = register_int_gauge!(opts!(
        "synack_analyzer_stats_dropped_count",
        "Number of packets dropped because there was no room in the operating system's buffer when they arrived, because packets weren't being read fast enough.",
        ).const_labels(COMMON_LABELS.to_owned())).unwrap();
    static ref PM_STATS_IF_DROPPED_COUNT: IntGauge = register_int_gauge!(opts!(
        "synack_analyzer_stats_if_dropped_count",
        "Number of packets dropped by the network interface or its driver.",
        ).const_labels(COMMON_LABELS.to_owned())).unwrap();
    static ref PM_STATS_IF_RECEIVED_COUNT: IntGauge = register_int_gauge!(opts!(
        "synack_analyzer_stats_received_count",
        "Number of packets received.",
        ).const_labels(COMMON_LABELS.to_owned())).unwrap();

    static ref PM_CORE_SYN_STRUCTURE_ITEMS: IntGaugeVec = register_int_gauge_vec!(opts!(
        "synack_core_syn_structure_items",
        "Number of item in the core structure.",
        ).const_labels(COMMON_LABELS.to_owned()),
        &["tag"]).unwrap();
    static ref PM_CORE_SYN_STRUCTURE_CAPACITY: IntGaugeVec = register_int_gauge_vec!(opts!(
        "synack_core_syn_structure_capacity",
        "Capacity of the core structure."
        ).const_labels(COMMON_LABELS.to_owned()),
        &["tag"]).unwrap();

    static ref PM_SYNACK_ANALYZER_INFO: IntGaugeVec = register_int_gauge_vec!(opts!(
        "synack_analyzer_info",
        "General info for the current synack-analyzer instance.",
        ).const_labels(COMMON_LABELS.to_owned()),
        &["device", "threshold_synack_ms"]).unwrap();
}

#[derive(Parser, Debug, Clone)]
#[command(author, version, about, long_about)]
/// Synack analyzer. Can be used on client side and also on server side.
/// Libpcap is internally used, it has to be installed as this is not a
/// statically-linked program. You have to be a root or have at least
/// CAP_NET_RAW capability.
struct Args {
    /// Threshold for SYNACK in ms
    ///
    /// When an synack is received after the specified threshold, syn and synack will be dump into file
    #[arg(short, long, env = "THRESHOLD_SYNACK_MS")]
    threshold_synack_ms: u32,

    /// Network interface
    ///
    /// Network interface to sniff packets
    #[arg(short, long, env = "INTERFACE", default_value = "any")]
    interface: Option<String>,

    /// Capture tcp RST packets
    ///
    /// Capture tcp RST packets
    #[arg(long, env = "CAPTURE_RESET_PACKETS", default_value = "false")]
    capture_reset_packets: bool,

    /// Destination port
    ///
    /// Destination port used in filtering
    #[arg(short, long, env = "DESTINATION_PORT", group = "bpf_filter_group")]
    destination_port: Option<u16>,

    /// Disable dumping
    ///
    /// Disable dumping late synack and syn packets into a file.
    #[arg(long, env = "DISABLE_DUMPING", default_value = "false")]
    disable_dumping: bool,

    /// Dump retrans packets
    ///
    /// Dump into file also Syn and SynAck retrans packets
    #[arg(long, env = "DUMP_RETRANS_PACKETS", default_value = "false")]
    dump_retrans_packets: bool,

    /// BPF filter
    ///
    /// Berkeley Packet Filter: https://biot.com/capstats/bpf.html
    #[arg(short, long, env = "BPF_FILTER", group = "bpf_filter_group")]
    bpf_filter: Option<String>,

    /// Output directory
    #[arg(short, long, env = "OUTDIR", default_value = ".")]
    output_dir: Option<PathBuf>,

    /// Immediate mode - libpcap
    ///
    /// In immediate mode, packets are always delivered as soon as they arrive, with no buffering
    #[arg(long, env = "IMMEDIATE_MODE", default_value = "false")]
    immediate_mode: bool,

    /// Promiscuous mode - libpcap
    ///
    /// Promiscuous mode or promisc mode is a feature that makes the ethernet card pass all traffic it received to the kernel
    #[arg(long, env = "PROMISCUOUS_MODE", default_value = "false")]
    promiscuous_mode: bool,

    /// Buffer Size - libpcap (use >2048)
    ///
    /// Buffer size for incoming packet data
    #[arg(long, env = "BUFFER_LIBPCAP_SIZE", default_value = "4200000")]
    buffer_libpcap_size: Option<i32>,

    /// Prometheus metrics port
    #[arg(long, env = "METRICS_PORT")]
    metrics_port: Option<u16>,
}

fn prepare_bpf(args: &Args) -> String {
    let tcp_reset_filter = if args.capture_reset_packets {
        "or (tcp[tcpflags] & (tcp-rst) != 0)"
    } else {
        ""
    };
    match &args.bpf_filter {
        Some(bpf_filter) => bpf_filter.clone(),
        None => {
            // SYN     = "tcp[13]=2"
            // SYN+ACK = "tcp[13]=18"
            match &args.destination_port {
                Some(dport) => {
                    format!(
                        "(tcp[13]=2 and dst port {}) or (tcp[13]=18 and src port {}) {}",
                        dport, dport, tcp_reset_filter,
                    )
                }
                None => format!("(tcp[13]=2) or (tcp[13]=18) {}", tcp_reset_filter),
            }
        }
    }
}

trait SlicedPacketCreator: Default {
    fn create_sliced_packet<'a, 'b>(&'a self, packet: &'b Packet) -> Result<SlicedPacketWithInfo<'b>, ReadError>;
}

#[derive(Default)]
struct AnyDeviceSlicedPacketCreator;

#[derive(Default)]
struct SpecificDeviceSlicedPacketCreator;

struct SlicedPacketWithInfo<'a> {
    sliced_packet: SlicedPacket<'a>,
    vlan_packet: bool,
    link_address_type: LinkAdressType, // TODO remove me
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
enum LinkAdressType {
    Ethernet,
    IPIP,
    Unknown,
}

impl SlicedPacketCreator for AnyDeviceSlicedPacketCreator {
    // see https://www.tcpdump.org/linktypes/LINKTYPE_LINUX_SLL.html
    fn create_sliced_packet<'a, 'b>(&'a self, packet: &'b Packet) -> Result<SlicedPacketWithInfo<'b>, ReadError> {
        let link_address_type = match u16::from_be_bytes([packet.data[2], packet.data[3]]) {
            0x0001 => LinkAdressType::Ethernet,
            0x0300 => LinkAdressType::IPIP,
            _ => LinkAdressType::Unknown,
        };

        let protocol_type = u16::from_be_bytes([packet.data[14], packet.data[15]]);
        match protocol_type {
            // 16bytes offset because of https://www.tcpdump.org/linktypes/LINKTYPE_LINUX_SLL.html
            0x8100 => {
                // 802.1Q
                SlicedPacket::from_ip(&packet.data[(16 + 4)..]).map(|sliced_packet| SlicedPacketWithInfo {
                    sliced_packet,
                    vlan_packet: true,
                    link_address_type,
                })
            }
            0x0800 | 0x86dd => {
                // IPv4 or IPv6
                SlicedPacket::from_ip(&packet.data[16..]).map(|sliced_packet| SlicedPacketWithInfo {
                    sliced_packet,
                    vlan_packet: false,
                    link_address_type,
                })
            }
            _ => Err(ReadError::UnexpectedEndOfSlice(protocol_type as usize)), // TODO better handling
        }
    }
}

impl SlicedPacketCreator for SpecificDeviceSlicedPacketCreator {
    fn create_sliced_packet<'a, 'b>(&'a self, packet: &'b Packet) -> Result<SlicedPacketWithInfo<'b>, ReadError> {
        // TODO ?? doesn't work if vlan header is before eth?
        SlicedPacket::from_ethernet(&packet.data).map(|sliced_packet| SlicedPacketWithInfo {
            sliced_packet,
            vlan_packet: false, // TODO not handled all possibilities
            link_address_type: LinkAdressType::Unknown,
        })
    }
}

trait PacketWritter {
    fn write(&mut self, packet: &Packet);
}

struct SaveFilePacketWritter {
    savefile: Savefile,
}
impl SaveFilePacketWritter {
    fn new(savefile: Savefile) -> Self {
        Self { savefile }
    }
}

impl PacketWritter for SaveFilePacketWritter {
    fn write(&mut self, packet: &Packet) {
        self.savefile.write(&packet);
        self.savefile.flush().expect("Cannot flush dump to the savefile.");
        // TODO do we really want to flash?
    }
}

struct EmptyPacketWritter {}
impl EmptyPacketWritter {
    fn new() -> Self {
        Self {}
    }
}
impl PacketWritter for EmptyPacketWritter {
    fn write(&mut self, _packet: &Packet) {}
}

struct SynAckDetector<T: SlicedPacketCreator, U: PacketWritter> {
    sliced_packed_creator: T,
    threshold_synack_ms: u32,
    capture_reset_packets: bool,
    threshold_synack_ms_str: String,
    vlan_packets: HashMap<TCPHandshakeKey, SynPacketOccurrence>,
    non_vlan_packets: HashMap<TCPHandshakeKey, SynPacketOccurrence>,
    dump_retrans_packets: bool,
    packet_writer: U,
}

impl<T: SlicedPacketCreator, U: PacketWritter> SynAckDetector<T, U> {
    pub fn new(packet_writer: U, args: &Args) -> Self {
        Self {
            threshold_synack_ms: args.threshold_synack_ms,
            dump_retrans_packets: args.dump_retrans_packets,
            capture_reset_packets: args.capture_reset_packets,
            sliced_packed_creator: Default::default(),
            vlan_packets: Default::default(),
            non_vlan_packets: Default::default(),
            threshold_synack_ms_str: args.threshold_synack_ms.to_string(),
            packet_writer,
        }
    }

    fn proces_packet(&mut self, packet: Packet) {
        PM_FILTERED_PROCESSED_PACKET_COUNT.inc();
        let sliced_packet_with_info = match self.sliced_packed_creator.create_sliced_packet(&packet) {
            Ok(sliced_packet) => sliced_packet,
            Err(err) => {
                PM_SYNACK_ANALYZER_ERRORS.with_label_values(&["sliced_packet_creation"]).inc();
                error!("Cannot create sliced packet: {}", err);
                return;
            }
        };
        let sliced_packet = sliced_packet_with_info.sliced_packet;
        let received_vlan_tagged_packet = sliced_packet_with_info.vlan_packet;

        match sliced_packet.transport {
            Some(TransportSlice::Tcp(tcp)) => match sliced_packet.ip {
                Some(InternetSlice::Ipv4(ip, _)) => {
                    let tcp_header = match TcpHeaderSlice::from_slice(tcp.slice()) {
                        Ok(tcp_header) => tcp_header,
                        Err(err) => {
                            PM_SYNACK_ANALYZER_ERRORS.with_label_values(&["tcp_header_deserialization"]).inc();
                            error!("Cannot deserialize TCP header: {}", err);
                            return;
                        }
                    };
                    let ip_header = match Ipv4Header::from_slice(ip.slice()) {
                        Ok((ip_header, _)) => ip_header,
                        Err(err) => {
                            PM_SYNACK_ANALYZER_ERRORS.with_label_values(&["ipv4_header_deserialization"]).inc();
                            error!("Cannot deserialize ipv4 header: {}", err);
                            return;
                        }
                    };

                    let ts = packet.header.ts;
                    let link_address_type = sliced_packet_with_info.link_address_type;

                    let fsyn = tcp_header.syn();
                    let fack = tcp_header.ack();

                    let sn = tcp_header.sequence_number();
                    let an = tcp_header.acknowledgment_number();
                    let sip = ip_header.source;
                    let sport = tcp_header.source_port();
                    let dip = ip_header.destination;
                    let dport = tcp_header.destination_port();

                    let vlan_or_non_vlan = if received_vlan_tagged_packet { "vlan" } else { "non_vlan" };
                    let packet_map = if received_vlan_tagged_packet {
                        &mut self.vlan_packets
                    } else {
                        &mut self.non_vlan_packets
                    };

                    let packet_info = || {
                        format!(
                            "{:>15?} {:5} => {:>15?} {:5} | CEUA-PRSF={}{}{}{}-{}{}{}{} | T={:>10}.{:0>6} | S={:<10} A={:<10} | {:>8} |",
                            std::net::IpAddr::from(sip),
                            sport,
                            std::net::IpAddr::from(dip),
                            dport,
                            tcp_header.cwr() as i32,
                            tcp_header.ece() as i32,
                            tcp_header.urg() as i32,
                            tcp_header.ack() as i32,
                            tcp_header.psh() as i32,
                            tcp_header.rst() as i32,
                            tcp_header.syn() as i32,
                            tcp_header.fin() as i32,
                            ts.tv_sec,
                            ts.tv_usec,
                            sn,
                            an,
                            vlan_or_non_vlan
                        )
                    };
                    trace!("{} Processing packet.", packet_info());

                    if self.capture_reset_packets && tcp_header.rst() {
                        warn!("{} Rst occurence", packet_info());
                        PM_RST_COUNT.with_label_values(&[vlan_or_non_vlan]).inc();
                        self.packet_writer.write(&packet);
                    }

                    if fsyn && !fack {
                        PM_SYN_COUNT.with_label_values(&[vlan_or_non_vlan]).inc();

                        let key = TCPHandshakeKey { sn, sip, sport, dip, dport };
                        match packet_map.get_mut(&key) {
                            None => {
                                packet_map.insert(key, SynPacketOccurrence::new(&packet, link_address_type));
                                trace!("{} SYN packet - 1. syn packet occurrence.", packet_info());
                            }
                            Some(syn_occurrence) => {
                                // if link_address_type != syn_occurrence.link_address_type {
                                //     return; // TODO not so good approach
                                // }
                                // PM_SYN_RETRANS_COUNT.with_label_values(&[vlan_or_non_vlan]).inc();
                                if self.dump_retrans_packets {
                                    warn!(
                                        "{} SYN Retrans - {}. packet occurrence",
                                        packet_info(),
                                        syn_occurrence.packet_viewed_count + 1
                                    );
                                    if syn_occurrence.packet_viewed_count == 1 {
                                        self.packet_writer.write(&packet);
                                        syn_occurrence.first_appeard_packet_dumped = true;
                                    }
                                    self.packet_writer.write(&packet);
                                }
                                syn_occurrence.packet_viewed_count += 1;
                            }
                        }
                    } else if fsyn && fack {
                        PM_SYNACK_COUNT.with_label_values(&[vlan_or_non_vlan]).inc();

                        let key = TCPHandshakeKey {
                            sn: an - 1,
                            sip: dip,
                            sport: dport,
                            dip: sip,
                            dport: sport,
                        };

                        let non_vlan_syn_packet = self.vlan_packets.remove(&key);
                        let vlan_syn_packet = self.non_vlan_packets.remove(&key);

                        if non_vlan_syn_packet.is_none() && vlan_syn_packet.is_none() {
                            debug!("{} Ignoring synack. We don't have vlan/non_vlan syn cached.", packet_info());
                            // PM_SYNACK_RETRANS_COUNT.with_label_values(&[vlan_or_non_vlan]).inc();
                            // if self.dump_retrans_packets {
                            //     warn!("{} SYNACK Retrans - SYN for delivered SYNACK was not cached", packet_info());
                            //     self.savefile.write(&packet);
                            //     self.savefile.flush().expect("Cannot flush dump to the savefile.");
                            // }
                        } else {
                            let synack_us = 1_000_000 * ts.tv_sec + ts.tv_usec;
                            let to_us = |tv_sec, tv_usec| 1_000_000 * tv_sec + tv_usec;

                            let synack_times = [non_vlan_syn_packet.as_ref(), vlan_syn_packet.as_ref()].map(|op| {
                                op.map(|p| to_us(p.first_appeared_packet.header.ts.tv_sec, p.first_appeared_packet.header.ts.tv_usec))
                                    .unwrap_or(i64::MAX)
                            });
                            let syn_occurrence = if synack_times[0] < synack_times[1] {
                                non_vlan_syn_packet.unwrap()
                            } else {
                                vlan_syn_packet.unwrap()
                            };
                            let syn_us = 1_000_000 * syn_occurrence.first_appeared_packet.header.ts.tv_sec
                                + syn_occurrence.first_appeared_packet.header.ts.tv_usec;

                            let delta_synack_syn_ms = ((synack_us - syn_us) / 1000) as u32;
                            PM_SYNACK_RESPONSE_TIME_MS.observe(delta_synack_syn_ms as f64);

                            debug!("{} SYNACK response time was {:>4} ms.", packet_info(), delta_synack_syn_ms);

                            if delta_synack_syn_ms >= self.threshold_synack_ms {
                                PM_SYNACK_LONG_RESPONSE_COUNT.with_label_values(&[&self.threshold_synack_ms_str]).inc();
                                warn!(
                                    "{} SYNACK response time was too long: {:>4} ms. Syn was seen {} times.",
                                    packet_info(),
                                    delta_synack_syn_ms,
                                    syn_occurrence.packet_viewed_count
                                );
                                if !syn_occurrence.first_appeard_packet_dumped {
                                    self.packet_writer.write(&packet);
                                }
                                self.packet_writer.write(&packet);
                            }
                        }
                    }
                }
                _ => {
                    PM_SYNACK_ANALYZER_ERRORS.with_label_values(&["ipv4_header_unrecognized"]).inc();
                    error!("IPv4 header was expected.")
                }
            },
            _ => {
                PM_SYNACK_ANALYZER_ERRORS.with_label_values(&["tcp_header_unrecognized"]).inc();
                error!("TCP header was expected.")
            }
        }
    }
}

#[derive(Hash, PartialEq, Eq, Debug)]
struct TCPHandshakeKey {
    sn: u32,
    sip: [u8; 4],
    sport: u16,
    dip: [u8; 4],
    dport: u16,
}

struct SynPacketOccurrence {
    first_appeared_packet: PacketCopy,
    first_appeard_packet_dumped: bool,
    packet_viewed_count: u32,
    link_address_type: LinkAdressType,
}

impl SynPacketOccurrence {
    fn new(packet: &Packet, link_address_type: LinkAdressType) -> Self {
        Self {
            first_appeared_packet: packet.into(),
            first_appeard_packet_dumped: false,
            packet_viewed_count: 1,
            link_address_type,
        }
    }
}

impl<'a> From<&'a PacketCopy> for Packet<'a> {
    fn from(packet_copy: &'a PacketCopy) -> Self {
        Packet {
            header: &packet_copy.header,
            data: &packet_copy.data,
        }
    }
}

struct PacketCopy {
    pub header: PacketHeader,
    pub data: Vec<u8>,
}

impl<'a> From<&Packet<'a>> for PacketCopy {
    fn from(packet: &Packet) -> Self {
        Self {
            header: packet.header.clone(),
            data: Vec::from(packet.data),
        }
    }
}

impl<T: SlicedPacketCreator, U: PacketWritter> SynAckDetector<T, U> {
    fn run_infinitely(mut self, mut cap: Capture<Active>) {
        loop {
            match cap.stats() {
                Ok(stats) => {
                    PM_STATS_DROPPED_COUNT.set(stats.dropped as i64);
                    PM_STATS_IF_RECEIVED_COUNT.set(stats.received as i64);
                    PM_STATS_IF_DROPPED_COUNT.set(stats.if_dropped as i64);
                }
                Err(err) => {
                    PM_SYNACK_ANALYZER_ERRORS.with_label_values(&["getting_capture_stats"]).inc();
                    error!("Cannot get capture stats: {}", err);
                }
            }

            PM_CORE_SYN_STRUCTURE_ITEMS
                .with_label_values(&["vlan"])
                .set(self.vlan_packets.len() as i64);
            PM_CORE_SYN_STRUCTURE_CAPACITY
                .with_label_values(&["vlan"])
                .set(self.vlan_packets.capacity() as i64);

            PM_CORE_SYN_STRUCTURE_ITEMS
                .with_label_values(&["non_vlan"])
                .set(self.non_vlan_packets.len() as i64);
            PM_CORE_SYN_STRUCTURE_CAPACITY
                .with_label_values(&["non_vlan"])
                .set(self.non_vlan_packets.capacity() as i64);

            match cap.next_packet() {
                Ok(packet) => self.proces_packet(packet),
                Err(err) => {
                    PM_SYNACK_ANALYZER_ERRORS.with_label_values(&["getting_packet_from_capture"]).inc();
                    error!("Cannot get packet from live capture: {}", err);
                }
            }
        }
    }
}

async fn metrics_handler() -> Result<impl Reply, Rejection> {
    use prometheus::Encoder;
    let encoder = prometheus::TextEncoder::new();

    let mut buffer = Vec::new();
    if let Err(e) = encoder.encode(&prometheus::gather(), &mut buffer) {
        error!("could not encode prometheus metrics: {}", e);
    };
    let res = match String::from_utf8(buffer.clone()) {
        Ok(v) => v,
        Err(e) => {
            error!("custom metrics could not be from_utf8'd: {}", e);
            String::default()
        }
    };
    buffer.clear();

    Ok(res)
}

fn init_logger(args: &Args) {
    use env_logger::{fmt::Color, Builder};

    let node_name = NODE_NAME.as_str();
    if env::var("RUST_LOG").is_err() {
        env::set_var("RUST_LOG", "info");
    }
    if env::var("RUST_LOG_STYLE").is_err() {
        env::set_var("RUST_LOG_STYLE", "auto");
    }
    Builder::new()
        .parse_default_env()
        .format(move |buf, record| {
            let mut level_style = buf.style();
            let ts = buf.timestamp();
            match record.level() {
                Level::Trace => level_style.set_color(Color::Cyan),
                Level::Debug => level_style.set_color(Color::Blue),
                Level::Info => level_style.set_color(Color::Green),
                Level::Warn => level_style.set_color(Color::Yellow),
                Level::Error => level_style.set_color(Color::Red).set_bold(true),
            };
            writeln!(buf, "({} {}) {:>5} {}", &node_name, ts, level_style.value(record.level()), record.args())
        })
        .init();
    info!("Started on node {} with arguments: {:?}", node_name, args);
}

macro_rules! dispatch_work {
    ($ty:ty, $args:expr, $cap:expr) => {{
        use crate::*;

        tokio::task::spawn(async move {
            if !$args.disable_dumping {
                let mut output_file = $args.output_dir.as_ref().unwrap().clone();
                output_file.push(Local::now().format(&format!("{}-%Y-%m-%d_%H-%M-%S.pcap", NODE_NAME.as_str())).to_string());
                info!("Filtered packets will be written into: {:?}", output_file);
                let savefile = $cap.savefile(&output_file).expect(&format!("Cannot create savefile: {:?}", output_file));
                SynAckDetector::<$ty, SaveFilePacketWritter>::new(SaveFilePacketWritter::new(savefile), &$args).run_infinitely($cap);
            } else {
                SynAckDetector::<$ty, EmptyPacketWritter>::new(EmptyPacketWritter::new(), &$args).run_infinitely($cap);
            }
        })
    }};
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let device = args.interface.as_ref().unwrap();
    let bpf = prepare_bpf(&args);

    init_logger(&args);

    match Device::list() {
        Err(err) => error!("Cannot list all devices via pcap_findalldevs: {}", err),
        Ok(devices) => {
            if devices.len() != 0 {
                info!("The following devices were found via pcap_findalldevs:");
            }
            for d in devices {
                info!("{:?} ", d);
            }
        }
    }

    fs::create_dir_all(args.output_dir.as_ref().unwrap()).expect("Cannot create output dir.");

    info!("Logging level: {}", env::var("RUST_LOG").unwrap_or("UNDEFINIED".to_string()));
    info!("Sniffing on interface: {}", device);
    info!("Filtering with BPF: {}", bpf);
    info!("Threshold for SYNACK response: {} ms", args.threshold_synack_ms);
    info!("Immediate mode active: {:?}", args.immediate_mode);

    PM_SYNACK_ANALYZER_INFO
        .with_label_values(&[device, &args.threshold_synack_ms.to_string()])
        .set(1);

    let mut cap = pcap::Capture::from_device(device.as_str())
        .expect(&format!("Cannot use interface: {}", device))
        .immediate_mode(args.immediate_mode)
        .snaplen(1024) // the maximum length of a packet captured into the buffer
        .buffer_size(args.buffer_libpcap_size.unwrap_or_default())
        .promisc(args.promiscuous_mode)
        .precision(Precision::Micro)
        .open()
        .expect("Cannot activate libpcap capture.");

    cap.filter(bpf.as_str(), true).expect(&format!("Cannot create bpf filter: {}", bpf));

    let metrics_port = args.metrics_port.clone();
    match args.interface.as_deref() {
        Some("any") | None => dispatch_work!(AnyDeviceSlicedPacketCreator, args, cap),
        Some(_) => dispatch_work!(SpecificDeviceSlicedPacketCreator, args, cap),
    };

    if metrics_port.is_some() {
        warp::serve(warp::path!("metrics").and_then(metrics_handler))
            .run(([0, 0, 0, 0], metrics_port.unwrap_or_default()))
            .await
    } else {
        thread::sleep(Duration::from_secs(u64::MAX));
    }
}
