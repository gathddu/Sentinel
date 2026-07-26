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

/// specific network interface by name
pub fn open_interface(name: &str) -> Capture<Active> {
    println!("Listening on: {}", name);

    Capture::from_device(name)
        .expect("Failed to open device")
        .snaplen(65535)
        .promisc(true)
        .timeout(1000)
        .open()
        .expect("Failed to start capture")
}
