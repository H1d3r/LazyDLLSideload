const RUST_KEYWORDS: &[&str] = &[
    "as", "async", "await", "break", "const", "continue", "crate", "dyn", "else", "enum", "extern",
    "false", "fn", "for", "if", "impl", "in", "let", "loop", "match", "mod", "move", "mut", "pub",
    "ref", "return", "self", "Self", "static", "struct", "super", "trait", "true", "try", "type",
    "typeof", "unsafe", "unsized", "use", "virtual", "where", "while", "yield", "abstract",
    "become", "box", "do", "final", "macro", "override", "priv", "gen",
];

pub fn is_rust_ident(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c == '_' || c.is_ascii_alphabetic() => {}
        _ => return false,
    }
    chars.all(|c| c == '_' || c.is_ascii_alphanumeric()) && !RUST_KEYWORDS.contains(&name)
}

pub fn rust_ident(name: &str) -> String {
    if is_rust_ident(name) {
        return name.to_string();
    }
    let mut out = String::new();
    for (i, c) in name.chars().enumerate() {
        if c.is_ascii_alphanumeric() || c == '_' {
            if i == 0 && c.is_ascii_digit() {
                out.push('_');
            }
            out.push(c);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() || out.chars().all(|c| c == '_') {
        out = format!("export_{}", simple_hash(name));
    }
    if out.chars().next().is_some_and(|c| c.is_ascii_digit()) {
        out.insert(0, '_');
    }
    if RUST_KEYWORDS.contains(&out.as_str()) {
        out.push('_');
    }
    out
}

pub fn cargo_package_name(stem: &str) -> String {
    let mut out = String::new();
    for c in stem.chars() {
        if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
            out.push(c);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        out = "sideload_dll".into();
    }
    if out.chars().next().is_some_and(|c| c.is_ascii_digit()) {
        out.insert(0, '_');
    }
    out
}

pub fn rust_string_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\u{{{:x}}}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn simple_hash(s: &str) -> u32 {
    let mut h: u32 = 5381;
    for b in s.bytes() {
        h = h.wrapping_mul(33).wrapping_add(b as u32);
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_plain_names() {
        assert_eq!(rust_ident("libvlc_new"), "libvlc_new");
        assert!(is_rust_ident("ShapingCreateFontCacheData"));
    }

    #[test]
    fn mangles_cpp_and_keywords() {
        assert_ne!(rust_ident("?foo@@YAXXZ"), "?foo@@YAXXZ");
        assert!(is_rust_ident(&rust_ident("?foo@@YAXXZ")));
        assert_eq!(rust_ident("type"), "type_");
        assert_eq!(rust_ident("123bad"), "_123bad");
    }

    #[test]
    fn package_names() {
        assert_eq!(cargo_package_name("TextShaping"), "TextShaping");
        assert_eq!(cargo_package_name("foo.bar"), "foo_bar");
        assert_eq!(cargo_package_name("1abc"), "_1abc");
    }

    #[test]
    fn escapes_paths() {
        assert_eq!(
            rust_string_escape(r"C:\Windows\System32\a.dll"),
            r"C:\\Windows\\System32\\a.dll"
        );
    }
}
