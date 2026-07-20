use pcap::Device;

fn main() {
    println!("Sentinel NIDS is starting..");

    let devices = Device::list().expect("Failed to list network devices");

    println!("Available network interfaces:");
    for device in &devices {
        let desc = device.desc.as_deref().unwrap_or("No description");
        println!("  {} — {}", device.name, desc);
    }
}
