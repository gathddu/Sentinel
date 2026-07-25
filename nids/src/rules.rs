use serde::Deserialize;
use std::fs;

/// detection rule: if the payload contains this pattern, fire an alert
#[derive(Deserialize)]
pub struct Rule {
    pub id: u32,
    pub name: String,
    pub pattern: String,
    pub severity: String,
}

#[derive(Deserialize)]
struct RuleFile {
    rules: Vec<Rule>,
}

/// load rules from YAML file
pub fn load(path: &str) -> Vec<Rule> {
    let contents = fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("Failed to read rules file '{}': {}", path, e));

    let file: RuleFile = serde_yaml::from_str(&contents)
        .unwrap_or_else(|e| panic!("Failed to parse rules file '{}': {}", path, e));

    file.rules
}
