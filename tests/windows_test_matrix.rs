//! Every test gate that runs on Linux but not on native Windows is listed in
//! tests/windows_test_matrix.toml with a reason and the issue that lifts it
//! (sr-winpar.16), and every listed gate still exists.
//!
//! The scan reads source text, so it runs on every platform. It evaluates each
//! `cfg` predicate twice, as Linux and as Windows, and keeps the gates that hold
//! on Linux and fail on Windows: `#![cfg]` on a file with tests, and `#[cfg]` on
//! a test function or on a module (inline, out of line or `#[path]`) that
//! contains tests. Cargo features are assumed enabled, so only platform
//! predicates decide.

use serde::Deserialize;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const REASONS: &[&str] = &[
    "private-storage",
    "subprocess",
    "hook-suite",
    "provider-stub",
    "unix-fixture",
    "unaudited",
    "linux-only",
    "unix-only",
    "platform-twin",
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Matrix {
    schema_version: u32,
    gate: Vec<Entry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    file: String,
    item: String,
    gate: String,
    reason: String,
    issue: String,
    #[serde(default)]
    also: Vec<String>,
    #[serde(default)]
    #[allow(dead_code)]
    note: Option<String>,
}

type Site = (String, String, String);

// ---------------------------------------------------------------------------
// cfg predicates

#[derive(Debug)]
enum Pred {
    All(Vec<Pred>),
    Any(Vec<Pred>),
    Not(Box<Pred>),
    Flag(String),
    KeyValue(String, String),
}

struct Target {
    flags: &'static [&'static str],
    os: &'static str,
    family: &'static str,
    env: &'static str,
}

const LINUX: Target = Target {
    flags: &["unix", "test"],
    os: "linux",
    family: "unix",
    env: "gnu",
};
const WINDOWS: Target = Target {
    flags: &["windows", "test"],
    os: "windows",
    family: "windows",
    env: "msvc",
};

fn tokens(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut chars = text.chars().peekable();
    while let Some(&c) = chars.peek() {
        if c.is_whitespace() {
            chars.next();
        } else if "(),=".contains(c) {
            out.push(c.to_string());
            chars.next();
        } else if c == '"' {
            chars.next();
            let mut s = String::from("\"");
            for d in chars.by_ref() {
                if d == '"' {
                    break;
                }
                s.push(d);
            }
            out.push(s);
        } else {
            let mut s = String::new();
            while let Some(&d) = chars.peek() {
                if d.is_alphanumeric() || d == '_' {
                    s.push(d);
                    chars.next();
                } else {
                    break;
                }
            }
            assert!(!s.is_empty(), "unexpected character {c:?} in cfg({text})");
            out.push(s);
        }
    }
    out
}

fn parse(tokens: &[String], at: &mut usize) -> Pred {
    let word = tokens[*at].clone();
    *at += 1;
    if matches!(word.as_str(), "all" | "any" | "not") && tokens.get(*at).is_some_and(|t| t == "(") {
        *at += 1;
        let mut args = Vec::new();
        while tokens[*at] != ")" {
            args.push(parse(tokens, at));
            if tokens[*at] == "," {
                *at += 1;
            }
        }
        *at += 1;
        return match word.as_str() {
            "all" => Pred::All(args),
            "any" => Pred::Any(args),
            _ => Pred::Not(Box::new(
                args.into_iter().next().expect("not() has one argument"),
            )),
        };
    }
    if tokens.get(*at).is_some_and(|t| t == "=") {
        let value = tokens[*at + 1].trim_start_matches('"').to_owned();
        *at += 2;
        return Pred::KeyValue(word, value);
    }
    Pred::Flag(word)
}

fn predicate(text: &str) -> Pred {
    let tokens = tokens(text);
    let mut at = 0;
    let pred = parse(&tokens, &mut at);
    assert_eq!(at, tokens.len(), "trailing tokens in cfg({text})");
    pred
}

fn holds(pred: &Pred, target: &Target) -> bool {
    match pred {
        Pred::All(args) => args.iter().all(|p| holds(p, target)),
        Pred::Any(args) => args.iter().any(|p| holds(p, target)),
        Pred::Not(inner) => !holds(inner, target),
        Pred::Flag(name) => target.flags.contains(&name.as_str()),
        Pred::KeyValue(key, value) => match key.as_str() {
            "feature" => true,
            "target_os" => target.os == value,
            "target_family" => target.family == value,
            "target_env" => target.env == value,
            _ => false,
        },
    }
}

/// The gate label when this attribute keeps an item on Linux but not Windows.
fn windows_gate(kind: &str, body: &str) -> Option<String> {
    if kind == "cfg" {
        let pred = predicate(body);
        return (holds(&pred, &LINUX) && !holds(&pred, &WINDOWS)).then(|| format!("cfg({body})"));
    }
    // cfg_attr(PRED, ignore): ignored where PRED holds.
    let mut depth = 0;
    for (index, c) in body.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => depth -= 1,
            ',' if depth == 0 => {
                let (pred, rest) = (&body[..index], body[index + 1..].trim());
                if rest != "ignore" && !rest.starts_with("ignore =") {
                    return None;
                }
                let pred_value = predicate(pred);
                return (holds(&pred_value, &WINDOWS) && !holds(&pred_value, &LINUX))
                    .then(|| format!("cfg_attr({pred}, ignore)"));
            }
            _ => {}
        }
    }
    None
}

// ---------------------------------------------------------------------------
// source scanning

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read_lines(path: &Path) -> Vec<String> {
    std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
        .lines()
        .map(str::to_owned)
        .collect()
}

fn is_attribute_or_comment(line: &str) -> bool {
    let line = line.trim_start();
    line.starts_with("#[") || line.starts_with("//")
}

fn contains_test(text: &str) -> bool {
    text.contains("#[test]")
}

/// `(name, inline)` for a `mod` declaration line.
fn module_declaration(line: &str) -> Option<(String, bool)> {
    let mut rest = line.trim_start();
    if let Some(after) = rest.strip_prefix("pub") {
        rest = after.trim_start();
        if rest.starts_with('(') {
            rest = rest[rest.find(')')? + 1..].trim_start();
        }
    }
    let rest = rest.strip_prefix("mod ")?.trim_start();
    let end = rest.find(|c: char| !(c.is_alphanumeric() || c == '_'))?;
    let (name, tail) = rest.split_at(end);
    match tail.trim_start().chars().next()? {
        ';' => Some((name.to_owned(), false)),
        '{' => Some((name.to_owned(), true)),
        _ => None,
    }
}

fn function_name(line: &str) -> Option<String> {
    let mut rest = line.trim_start();
    for prefix in ["pub(crate) ", "pub ", "async "] {
        rest = rest.strip_prefix(prefix).unwrap_or(rest);
    }
    let rest = rest.strip_prefix("fn ")?;
    let end = rest.find(|c: char| !(c.is_alphanumeric() || c == '_'))?;
    Some(rest[..end].to_owned())
}

fn path_attribute(attributes: &str) -> Option<String> {
    let start = attributes.find("#[path")?;
    let rest = &attributes[start..];
    let open = rest.find('"')? + 1;
    let close = open + rest[open..].find('"')?;
    Some(rest[open..close].to_owned())
}

/// The file of an out-of-line module, following Rust's lookup rules.
fn module_file(declaring: &Path, name: &str, attributes: &str) -> Option<PathBuf> {
    let dir = declaring.parent()?;
    if let Some(path) = path_attribute(attributes) {
        let file = dir.join(path);
        return file.is_file().then_some(file);
    }
    let stem = declaring.file_stem()?.to_str()?;
    let base = if matches!(stem, "lib" | "main" | "mod") {
        dir.to_path_buf()
    } else {
        dir.join(stem)
    };
    [
        base.join(format!("{name}.rs")),
        base.join(name).join("mod.rs"),
    ]
    .into_iter()
    .find(|file| file.is_file())
}

fn attributes_before(lines: &[String], index: usize) -> String {
    let mut start = index;
    while start > 0 && is_attribute_or_comment(&lines[start - 1]) {
        start -= 1;
    }
    lines[start..index].join("\n")
}

fn file_has_tests(path: &Path, seen: &mut BTreeSet<PathBuf>) -> bool {
    if !seen.insert(path.to_path_buf()) {
        return false;
    }
    let lines = read_lines(path);
    if contains_test(&lines.join("\n")) {
        return true;
    }
    lines.iter().enumerate().any(|(index, line)| {
        module_declaration(line).is_some_and(|(name, inline)| {
            !inline
                && module_file(path, &name, &attributes_before(&lines, index))
                    .is_some_and(|file| file_has_tests(&file, seen))
        })
    })
}

fn block_text(lines: &[String], start: usize) -> String {
    let mut depth = 0i64;
    let mut opened = false;
    let mut end = lines.len();
    for (index, line) in lines.iter().enumerate().skip(start) {
        for c in line.chars() {
            match c {
                '{' => {
                    depth += 1;
                    opened = true;
                }
                '}' => depth -= 1,
                _ => {}
            }
        }
        if opened && depth == 0 {
            end = index + 1;
            break;
        }
    }
    lines[start..end].join("\n")
}

fn scan_file(path: &Path, relative: &str, sites: &mut BTreeSet<Site>) {
    let lines = read_lines(path);
    for (index, line) in lines.iter().enumerate() {
        // A trailing comment does not change the attribute.
        let trimmed = line.split(" //").next().unwrap_or_default().trim();
        let (inner, rest) = if let Some(rest) = trimmed.strip_prefix("#![") {
            (true, rest)
        } else if let Some(rest) = trimmed.strip_prefix("#[") {
            (false, rest)
        } else {
            continue;
        };
        let Some(rest) = rest.strip_suffix(")]") else {
            continue;
        };
        let (kind, body) = if let Some(body) = rest.strip_prefix("cfg_attr(") {
            ("cfg_attr", body)
        } else if let Some(body) = rest.strip_prefix("cfg(") {
            ("cfg", body)
        } else {
            continue;
        };
        let Some(gate) = windows_gate(kind, body) else {
            continue;
        };
        if inner {
            if file_has_tests(path, &mut BTreeSet::new()) {
                sites.insert((relative.to_owned(), "*".to_owned(), gate));
            }
            continue;
        }
        let mut item = index + 1;
        while item < lines.len()
            && (is_attribute_or_comment(&lines[item]) || lines[item].trim().is_empty())
        {
            item += 1;
        }
        let Some(target) = lines.get(item) else {
            continue;
        };
        let attributes = lines[index..item].join("\n");
        if let Some(name) = function_name(target) {
            if contains_test(&attributes) {
                sites.insert((relative.to_owned(), name, gate));
            }
        } else if let Some((name, inline)) = module_declaration(target) {
            let has_tests = if inline {
                contains_test(&block_text(&lines, item))
            } else {
                module_file(path, &name, &attributes)
                    .is_some_and(|file| file_has_tests(&file, &mut BTreeSet::new()))
            };
            if has_tests {
                sites.insert((relative.to_owned(), format!("mod {name}"), gate));
            }
        }
    }
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            walk(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

fn scanned_sites() -> BTreeSet<Site> {
    let root = root();
    let mut sites = BTreeSet::new();
    for top in ["src", "tests"] {
        let mut files = Vec::new();
        walk(&root.join(top), &mut files);
        for file in files {
            let relative = file
                .strip_prefix(&root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            scan_file(&file, &relative, &mut sites);
        }
    }
    sites
}

fn known_issue_ids() -> BTreeSet<String> {
    // The tracker export is checked in; the matrix may cite only real issues.
    let issues = std::fs::read_to_string(root().join(".beads/issues.jsonl"))
        .expect("the checked-in .beads/issues.jsonl names the issues the matrix cites");
    issues
        .lines()
        .filter_map(|line| {
            let value: serde_json::Value = serde_json::from_str(line).ok()?;
            value["id"].as_str().map(str::to_owned)
        })
        .collect()
}

// ---------------------------------------------------------------------------
// tests

#[test]
fn cfg_predicates_are_evaluated_per_platform() {
    let windows_gated = |body: &str| windows_gate("cfg", body).is_some();
    assert!(windows_gated("unix"));
    assert!(windows_gated("all(test, unix)"));
    assert!(windows_gated(
        r#"any(target_os = "linux", target_os = "macos")"#
    ));
    assert!(windows_gated(r#"target_os = "linux""#));
    assert!(windows_gated("not(windows)"));
    assert!(!windows_gated("windows"));
    assert!(!windows_gated("test"));
    assert!(!windows_gated(r#"target_os = "macos""#));
    assert!(!windows_gated(r#"feature = "tui""#));
    assert!(windows_gate("cfg_attr", "windows, ignore").is_some());
    assert!(windows_gate("cfg_attr", "not(unix), ignore = \"needs a FIFO\"").is_some());
    assert!(windows_gate("cfg_attr", "not(unix), allow(dead_code)").is_none());
    assert!(windows_gate("cfg_attr", "unix, ignore").is_none());
}

#[test]
fn every_windows_excluded_test_gate_is_listed_with_a_reason_and_an_issue() {
    let text = std::fs::read_to_string(root().join("tests/windows_test_matrix.toml")).unwrap();
    let matrix: Matrix = toml::from_str(&text).unwrap();
    assert_eq!(matrix.schema_version, 1);
    let issues = known_issue_ids();

    let mut listed = BTreeSet::new();
    for entry in &matrix.gate {
        let site = (entry.file.clone(), entry.item.clone(), entry.gate.clone());
        assert!(
            listed.insert(site),
            "duplicate entry {} {}",
            entry.file,
            entry.item
        );
        assert!(
            REASONS.contains(&entry.reason.as_str()),
            "{} {}: unknown reason {}",
            entry.file,
            entry.item,
            entry.reason
        );
        let permanent = entry
            .issue
            .strip_prefix("permanent: ")
            .is_some_and(|reason| reason.trim().len() >= 10);
        assert!(
            permanent || issues.contains(&entry.issue),
            "{} {}: issue {:?} is neither a tracker ID nor a justified permanent reason",
            entry.file,
            entry.item,
            entry.issue
        );
        for also in &entry.also {
            assert!(
                issues.contains(also),
                "{} {}: unknown issue {also}",
                entry.file,
                entry.item
            );
        }
    }

    let scanned = scanned_sites();
    let missing: Vec<_> = scanned.difference(&listed).collect();
    let stale: Vec<_> = listed.difference(&scanned).collect();
    assert!(
        missing.is_empty() && stale.is_empty(),
        "tests/windows_test_matrix.toml is out of date.\nGates missing from the matrix: {missing:#?}\nEntries whose gate no longer exists: {stale:#?}"
    );
}
