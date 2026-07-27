use crate::rules::Rule;
use aho_corasick::AhoCorasick;

pub struct DetectionEngine {
    detector: AhoCorasick,
}

impl DetectionEngine {
    pub fn new(rules: &[Rule]) -> Self {
        let patterns: Vec<String> = rules.iter().map(|r| r.pattern.clone()).collect();

        let detector = AhoCorasick::new(patterns)
            .expect("Failed to build Aho-Corasick detector");

        Self { detector }
    }

/// check packet's raw bytes against all rules.
    pub fn inspect<'a>(&self, data: &[u8], rules: &'a [Rule]) -> Vec<&'a Rule> {
        let mut matches = Vec::new();

        for mat in self.detector.find_iter(data) {
            let rule_index = mat.pattern().as_usize();
            matches.push(&rules[rule_index]);
        }

        matches
    }
}
