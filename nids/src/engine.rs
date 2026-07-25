use crate::rules::Rule;

/// check packet's raw bytes against all rules.
/// returns a list of rules that matched.
pub fn inspect<'a>(data: &[u8], rules: &'a [Rule]) -> Vec<&'a Rule> {
    let mut matches = Vec::new();

    for rule in rules {
        if data.windows(rule.pattern.len()).any(|w| w == rule.pattern) {
            matches.push(rule);
        }
    }

    matches
}
