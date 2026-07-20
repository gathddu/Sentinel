use pcap::{Capture, Device};

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
        println!(
            "Packet #{}: {} bytes captured",
            count,
            packet.data.len()
        );

        if count >= 10 {
            break;
        }
    }

    println!("\nDone. Captured {} packets.", count);
}
