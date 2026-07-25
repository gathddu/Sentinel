use pcap::{Capture, Active, Device};

/// default network interface for packet capture
pub fn open_default() -> Capture<Active> {
    let device = Device::lookup()
        .expect("Failed to lookup device")
        .expect("No device found");

    println!("Listening on: {}", device.name);

    Capture::from_device(device)
        .expect("Failed to open device")
        .snaplen(65535)
        .promisc(true)
        .timeout(1000)
        .open()
        .expect("Failed to start capture")
}
