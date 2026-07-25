/// detection rule: if the payload contains this pattern, fire an alert
pub struct Rule {
    pub id: u32,
    pub name: &'static str,
    pub pattern: &'static [u8],
    pub severity: &'static str,
}

/// load the ruleset.
/// hardcoded for now
pub fn load() -> Vec<Rule> {
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
