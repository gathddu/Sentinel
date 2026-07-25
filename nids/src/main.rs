use pcap::{Capture, Device};
use etherparse::SlicedPacket;

/// detection rule: if the payload contains this patterns, fire an alert
struct Rule {
    id: u32,
    name: &'static str,
    pattern: &'static [u8],
    severity: &'static str,
}

/// hardcoded for now, later loaded from files
fn load_rules() -> Vec<Rule> {
    vec![
        Rule {
            id: 1001,
            name: "SQL Injection attempt",
            pattern: b"' OR '1'='1",
            severity: "CRITICAL",
        },
        Rule {
            id: 1002,
            name: "SQL Injection (UNION SELECT)",
            pattern: b"UNION SELECT",
            severity: "CRITICAL",
        },
        Rule {
            id: 1003,
            name: "XSS attempt (script tag)",
            pattern: b"<script>",
            severity: "HIGH",
        },
        Rule {
            id: 1004,
            name: "Path Traversal attempt",
            pattern: b"../../",
            severity: "HIGH",
        },
        Rule {
            id: 1005,
            name: "Command Injection (etc/passwd)",
            pattern: b"/etc/passwd",
            severity: "CRITICAL",
        },
        Rule {
            id: 1006,
            name: "Shellshock attempt",
            pattern: b"() { :;};",
            severity: "CRITICAL",
        },
    ]
}

fn main() {
    println!("Sentinel NIDS is starting..");

    let rules = load_rules();
    println!("Loaded {} detection rules.", rules.len());

    let device = Device::lookup()
        .expect("Failed to lookup device")
        .expect("No device found");

    println!("Listening on: {}", device.name);

    let mut cap = Capture::from_device(device)
        .expect("Failed to open device")
        .snaplen(65535)
        .promisc(true)
        .timeout(1000)
        .open()
        .expect("Failed to start capture");

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

        let payload = packet.data;

        for rule in &rules {
            if payload.windows(rule.pattern.len()).any(|w| w == rule.pattern) {
                alert_count += 1;
                println!(
                    "[ALERT] [{}] [{}] {} | {}:{} -> {}:{} | payload: {} bytes",
                    rule.severity, rule.id, rule.name,
                    src_ip, src_port, dst_ip, dst_port, payload.len()
                );
            }
        }

        if packet_count % 1000 == 0 {
            println!("... {} packets processed, {} alerts fired", packet_count, alert_count);
        }
    }
}
