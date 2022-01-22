use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::PathBuf,
};

use clap::Parser;
use color_eyre::Result;
use etherparse::PacketHeaders;
use human_bytes::human_bytes;
use pcap::{Capture, Packet};
use solana_sdk::{
    pubkey::Pubkey, sanitize::Sanitize, signature::Signature, transaction::Transaction,
};

#[derive(Parser, Debug)]
#[clap()]
struct Args {
    /// List of pcaps to load
    #[clap()]
    pcaps: Vec<PathBuf>,

    #[clap(long, short)]
    tpu_addr: Option<String>,
}

#[derive(Debug, Default)]
struct Stats {
    signatures: HashMap<Signature, u64>,
    program_invocations: HashMap<Pubkey, u64>,
    fee_payers: HashMap<Pubkey, u64>,
    unsanitized_transactions: u64,
    total_amount_of_packets: u64,
    total_traffic: usize,
}

#[derive(Debug, Default)]
struct Aggregation {
    stats_by_ip: HashMap<IpAddr, Stats>,
}

fn main() -> Result<()> {
    color_eyre::install()?;
    let args = Args::parse();

    let tpu_addr: Option<SocketAddr> = args
        .tpu_addr
        .as_ref()
        .map(|s| s.parse().expect("invalid tpu address"));

    let mut agg = Aggregation::default();

    for pcap_file in args.pcaps.iter() {
        let mut pcap = Capture::from_file(pcap_file)?;
        if let Some(tpu_addr) = tpu_addr {
            pcap.filter(
                format!(
                    "ip dst host {} and udp dst port {}",
                    tpu_addr.ip(),
                    tpu_addr.port()
                )
                .as_str(),
                true,
            )?;
        } else {
            pcap.filter("udp", true)?;
        }
        while let Ok(packet) = pcap.next() {
            process_packet(packet, &mut agg)?;
        }
    }

    println!("total amount of ips: {}", agg.stats_by_ip.len());
    println!("");
    println!("");

    let mut stats_by_total_packet_amt = agg.stats_by_ip.drain().collect::<Vec<_>>();
    stats_by_total_packet_amt.sort_unstable_by_key(|s| -(s.1.total_traffic as i64));

    for (ip, stats) in stats_by_total_packet_amt.iter() {
        let avg_duplicates = if stats.signatures.len() > 0 {
            stats.signatures.values().sum::<u64>() as f64 / stats.signatures.len() as f64
        } else {
            0.0
        };

        let most_invoked_program = stats
            .program_invocations
            .iter()
            .max_by_key(|(_, v)| *v)
            .map(|(k, _)| k);

        let most_invoked_program_share = if let Some(most_invoked_program) = most_invoked_program {
            *stats.program_invocations.get(most_invoked_program).unwrap() as f64
                / stats.program_invocations.values().sum::<u64>() as f64
        } else {
            0.0
        };

        let most_occuring_fee_payers = stats
            .fee_payers
            .iter()
            .max_by_key(|(_, v)| *v)
            .map(|(k, _)| k);
        let most_occuring_fee_payers_share =
            if let Some(most_occuring_fee_payers) = most_occuring_fee_payers {
                *stats.fee_payers.get(most_occuring_fee_payers).unwrap() as f64
                    / stats.fee_payers.values().sum::<u64>() as f64
            } else {
                0.0
            };

        println!("sender: {}", ip);
        println!(
            "  total traffic: {}",
            human_bytes(stats.total_traffic as f64)
        );
        println!(
            "  total amount of packets: {}",
            stats.total_amount_of_packets
        );
        println!(
            "  unsanitized transactions: {}",
            stats.unsanitized_transactions
        );
        println!("  avg duplicates: {:.2}", avg_duplicates);
        println!(
            "  most invoked program: {:?} ({:.2} %)",
            most_invoked_program,
            most_invoked_program_share * 100.0
        );
        println!(
            "  most often occuring fee payer: {:?} ({:.2} %)",
            most_occuring_fee_payers,
            most_occuring_fee_payers_share * 100.0
        );
        println!("");
    }

    Ok(())
}

fn process_packet(packet: Packet, agg: &mut Aggregation) -> Result<()> {
    let data_len = packet.len();
    let packet = PacketHeaders::from_ethernet_slice(&packet)?;

    let ip_header = packet.ip.unwrap();
    let source_ip = match ip_header {
        etherparse::IpHeader::Version4(header, _) => IpAddr::V4(Ipv4Addr::from(header.source)),
        etherparse::IpHeader::Version6(header, _) => IpAddr::V6(Ipv6Addr::from(header.source)),
    };

    let stats = agg.stats_by_ip.entry(source_ip).or_default();

    stats.total_amount_of_packets += 1;
    stats.total_traffic += data_len;

    if let Ok(tx) = bincode::deserialize::<Transaction>(packet.payload) {
        if tx.sanitize().is_err() {
            stats.unsanitized_transactions += 1;
            return Ok(());
        }

        let fee_payer = tx.message.account_keys[0];
        *stats.fee_payers.entry(fee_payer).or_default() += 1;

        let occurences = stats.signatures.entry(tx.signatures[0]).or_default();

        if *occurences == 0 {
            for instruction in tx.message.instructions.iter() {
                let program_id = instruction.program_id(&tx.message.account_keys);
                *stats.program_invocations.entry(*program_id).or_default() += 1;
            }
        }

        *occurences += 1;
    } else {
        stats.unsanitized_transactions += 1;
    }

    Ok(())
}
