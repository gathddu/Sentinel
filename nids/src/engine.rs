use crate::rules::Rule;

/// check packet's raw bytes against all rules.
pub fn inspect<'a>(data: &[u8], rules: &'a [Rule]) -> Vec<&'a Rule> {
    let mut matches = Vec::new();

    for rule in rules {
        let pattern = rule.pattern.as_bytes();
        if data.windows(pattern.len()).any(|w| w == pattern) {
            matches.push(rule);
        }
    }

    matches
}
