mod capture;
mod rules;
mod engine;
mod alert;

use etherparse::SlicedPacket;
use std::sync::mpsc;
use std::thread;

fn main() {
    println!("Sentinel NIDS is starting..");

    let rules = rules::load("rules.yaml");
    println!("Loaded {} detection rules.", rules.len());

    let (tx, rx) = mpsc::sync_channel::<Vec<u8>>(10_000);

    let capture_handle = thread::spawn(move || {
        let mut cap = capture::open_default();
        println!("Monitoring traffic....\n");

        while let Ok(packet) = cap.next_packet() {
            if tx.send(packet.data.to_vec()).is_err() {
                break;
            }
        }
    });

    let mut packet_count: u64 = 0;
    let mut alert_count: u64 = 0;

    for data in rx {
        packet_count += 1;

        let parsed = match SlicedPacket::from_ethernet(&data) {
            Ok(p) => p,
            Err(_) => continue,
        };

        // extract IP addresses
        let (src_ip, dst_ip) = match &parsed.net {
            Some(etherparse::NetSlice::Ipv4(ipv4)) => (
                format!("{}", ipv4.header().source_addr()),
                format!("{}", ipv4.header().destination_addr()),
            ),
            Some(etherparse::NetSlice::Ipv6(ipv6)) => (
                format!("{}", ipv6.header().source_addr()),
                format!("{}", ipv6.header().destination_addr()),
            ),
            None => continue, // skip non-IP packets
        };

        // extract ports and protocol
        let (src_port, dst_port) = match &parsed.transport {
            Some(etherparse::TransportSlice::Tcp(tcp)) => {
                (tcp.source_port(), tcp.destination_port())
            }
            Some(etherparse::TransportSlice::Udp(udp)) => {
                (udp.source_port(), udp.destination_port())
            }
            _ => (0, 0),
        };

        // run detection engine on raw packet bytes
        let hits = engine::inspect(&data, &rules);

        for rule in hits {
            alert_count += 1;
            let a = alert::Alert::new(
                rule.id,
                &rule.name,
                &rule.severity,
                &src_ip,
                src_port,
                &dst_ip,
                dst_port,
                data.len(),
            );
            println!("{}", a.to_json());
        }

        if packet_count % 1000 == 0 {
            println!("... {} packets processed, {} alerts fired", packet_count, alert_count);
        }
    }

    capture_handle.join().unwrap();
}
