mod capture;
mod rules;
mod engine;

use etherparse::SlicedPacket;

fn main() {
    println!("Sentinel NIDS is starting..");

    let rules = rules::load();
    println!("Loaded {} detection rules.", rules.len());

    let mut cap = capture::open_default();
    println!("Monitoring traffic....\n");

    let mut packet_count: u64 = 0;
    let mut alert_count: u64 = 0;

    while let Ok(packet) = cap.next_packet() {
        packet_count += 1;

        let parsed = match SlicedPacket::from_ethernet(packet.data) {
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
        let hits = engine::inspect(packet.data, &rules);

        for rule in hits {
                alert_count += 1;
                println!(
                    "[ALERT] [{}] [{}] {} | {}:{} -> {}:{} | payload: {} bytes",
                    rule.severity, rule.id, rule.name,
                    src_ip, src_port, dst_ip, dst_port, packet.data.len()
                );
        }

        if packet_count % 1000 == 0 {
            println!("... {} packets processed, {} alerts fired", packet_count, alert_count);
        }
    }
}
