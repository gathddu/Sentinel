use pcap::{Capture, Device};
use etherparse::SlicedPacket;

fn main() {
    println!("Sentinel NIDS is starting..");

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

    println!("Capturing packets..\n");

    let mut count: u64 = 0;

    while let Ok(packet) = cap.next_packet() {
        count += 1;

        match SlicedPacket::from_ethernet(packet.data) {
            Ok(parsed) => {

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
                let (proto, src_port, dst_port) = match &parsed.transport {
                    Some(etherparse::TransportSlice::Tcp(tcp)) => {
                        ("TCP", tcp.source_port(), tcp.destination_port())
                    }
                    Some(etherparse::TransportSlice::Udp(udp)) => {
                        ("UDP", udp.source_port(), udp.destination_port())
                    }
                    _ => ("OTHER", 0, 0),
                };

                println!(
                    "#{} {} {}:{} -> {}:{} ({} bytes)",
                    count, proto, src_ip, src_port, dst_ip, dst_port, packet.data.len()
                );
            }
            Err(_) => {
                println!("#{} [unparseable] {} bytes", count, packet.data.len());
            }
        }

        if count >= 10 {
            break;
        }
    }

    println!("\nDone. Captured {} packets.", count);
}
