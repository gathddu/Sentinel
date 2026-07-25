use chrono::Utc;
use serde::Serialize;

#[derive(Serialize)]
pub struct Alert {
    pub timestamp: String,
    pub rule_id: u32,
    pub rule_name: String,
    pub severity: String,
    pub src_ip: String,
    pub src_port: u16,
    pub dst_ip: String,
    pub dst_port: u16,
    pub packet_len: usize,
}

impl Alert {
    pub fn new(
        rule_id: u32,
        rule_name: &str,
        severity: &str,
        src_ip: &str,
        src_port: u16,
        dst_ip: &str,
        dst_port: u16,
        packet_len: usize,
    ) -> Self {
        Self {
            timestamp: Utc::now().to_rfc3339(),
            rule_id,
            rule_name: rule_name.to_string(),
            severity: severity.to_string(),
            src_ip: src_ip.to_string(),
            src_port,
            dst_ip: dst_ip.to_string(),
            dst_port,
            packet_len,
        }
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap()
    }
}
