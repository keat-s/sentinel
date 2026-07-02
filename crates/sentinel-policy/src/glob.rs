//! Minimal wildcard matching: `*` (any run, including empty) and `?` (any
//! single character). Deliberately not full glob syntax — policy patterns
//! should stay simple enough to audit by eye.

/// Match `text` against `pattern` where `*` matches any (possibly empty) run
/// of characters and `?` matches exactly one character.
pub fn wildcard_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    let mut star: Option<usize> = None;
    let mut mark = 0usize;

    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

#[cfg(test)]
mod tests {
    use super::wildcard_match;

    #[test]
    fn exact_and_wildcards() {
        assert!(wildcard_match("send_email", "send_email"));
        assert!(!wildcard_match("send_email", "send_emails"));
        assert!(wildcard_match("*", ""));
        assert!(wildcard_match("*", "anything"));
        assert!(wildcard_match("delete_*", "delete_all_emails"));
        assert!(!wildcard_match("delete_*", "list_inbox"));
        assert!(wildcard_match("*_prod_*", "deploy_prod_eu"));
        assert!(wildcard_match("a?c", "abc"));
        assert!(!wildcard_match("a?c", "ac"));
        assert!(wildcard_match("*@evil.com", "attacker@evil.com"));
        assert!(!wildcard_match("*@evil.com", "me@example.com"));
    }

    #[test]
    fn star_backtracking() {
        assert!(wildcard_match("*ab*ab*", "xxabyyabzz"));
        assert!(!wildcard_match("*ab*ab*", "xxabyy"));
    }
}
