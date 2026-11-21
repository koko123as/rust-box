//! `rust-box rule-set`, following sing-box's `cmd/sing-box/cmd_rule_set*.go`:
//! `compile`, `decompile`, `format`, `upgrade`, `merge`, `match` and
//! `convert`.

use std::io::{Read, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context as _, Result};
use clap::Subcommand;
use rb_common::gojson;
use rb_config::rule_set::{
    FORMAT_BINARY, FORMAT_SOURCE, RULE_SET_VERSION_1, RULE_SET_VERSION_2, RULE_SET_VERSION_CURRENT,
};
use rb_config::{srs, HeadlessRule, PlainRuleSet, PlainRuleSetCompat};
use serde_json::Value;

const COMPILE_DEFAULT_OUTPUT: &str = "<file_name>.srs";
const DECOMPILE_DEFAULT_OUTPUT: &str = "<file_name>.json";

#[derive(Subcommand)]
pub enum RuleSetCommand {
    /// Compile rule-set json to binary
    Compile {
        #[arg(value_name = "source-path")]
        source: String,
        /// Output file
        #[arg(short = 'o', long = "output", default_value = COMPILE_DEFAULT_OUTPUT)]
        output: String,
    },
    /// Decompile rule-set binary to json
    Decompile {
        #[arg(value_name = "binary-path")]
        source: String,
        /// Output file
        #[arg(short = 'o', long = "output", default_value = DECOMPILE_DEFAULT_OUTPUT)]
        output: String,
    },
    /// Format rule-set json
    Format {
        #[arg(value_name = "source-path")]
        source: String,
        /// write result to (source) file instead of stdout
        #[arg(short = 'w', long = "write")]
        write: bool,
    },
    /// Upgrade rule-set json
    Upgrade {
        #[arg(value_name = "source-path")]
        source: String,
        /// write result to (source) file instead of stdout
        #[arg(short = 'w', long = "write")]
        write: bool,
    },
    /// Merge rule-set source files
    Merge {
        #[arg(value_name = "output-path")]
        output: String,
        /// set input rule-set file path
        #[arg(short = 'c', long = "config")]
        config: Vec<String>,
        /// set input rule-set directory path
        #[arg(short = 'C', long = "config-directory")]
        config_directory: Vec<String>,
    },
    /// Check if an IP address or a domain matches the rule-set
    Match {
        #[arg(value_name = "rule-set path")]
        source: String,
        #[arg(value_name = "IP address/domain")]
        target: String,
        /// rule-set format
        #[arg(short = 'f', long = "format", default_value = FORMAT_SOURCE)]
        format: String,
    },
    /// Convert adguard DNS filter to rule-set
    Convert {
        #[arg(value_name = "source-path")]
        source: String,
        /// Source type, available: adguard
        #[arg(short = 't', long = "type", default_value = "")]
        kind: String,
        /// Output file
        #[arg(short = 'o', long = "output", default_value = COMPILE_DEFAULT_OUTPUT)]
        output: String,
    },
}

pub fn run(command: RuleSetCommand) -> Result<()> {
    match command {
        RuleSetCommand::Compile { source, output } => compile(&source, &output),
        RuleSetCommand::Decompile { source, output } => decompile(&source, &output),
        RuleSetCommand::Format { source, write } => format(&source, write),
        RuleSetCommand::Upgrade { source, write } => upgrade(&source, write),
        RuleSetCommand::Merge { output, config, config_directory } => merge(&output, &config, &config_directory),
        RuleSetCommand::Match { source, target, format } => match_rule_set(&source, &target, format),
        RuleSetCommand::Convert { source, kind, output } => convert(&source, &kind, &output),
    }
}

/// Reads the source path, `stdin` meaning standard input.
fn read_source(path: &str) -> Result<Vec<u8>> {
    let mut content = Vec::new();
    if path == "stdin" {
        std::io::stdin().read_to_end(&mut content)?;
    } else {
        content = std::fs::read(path).with_context(|| format!("open {path}"))?;
    }
    Ok(content)
}

fn output_path(source: &str, output: &str, default: &str, suffix: &str, new_suffix: &str) -> String {
    if output != default {
        return output.to_string();
    }
    match source.strip_suffix(suffix) {
        Some(stem) => format!("{stem}{new_suffix}"),
        None => format!("{source}{new_suffix}"),
    }
}

fn parse_source(content: &[u8]) -> Result<PlainRuleSetCompat> {
    PlainRuleSetCompat::parse(content).map_err(|e| anyhow!(e))
}

fn write_binary(path: &str, rule_set: &PlainRuleSet, version: u8) -> Result<()> {
    let data = srs::write(rule_set, version).map_err(|e| anyhow!(e.0))?;
    std::fs::write(path, data).with_context(|| format!("open {path}"))?;
    Ok(())
}

fn compile(source: &str, output: &str) -> Result<()> {
    let content = read_source(source)?;
    let plain = parse_source(&content)?;
    let path = output_path(source, output, COMPILE_DEFAULT_OUTPUT, ".json", ".srs");
    write_binary(&path, &plain.options, srs::downgrade_version(plain.version, &plain.options))
}

fn decompile(source: &str, output: &str) -> Result<()> {
    let content = read_source(source)?;
    let rule_set = srs::read(&content, true).map_err(|e| anyhow!(e.0))?;
    if HeadlessRule::any_default(&rule_set.options.rules, &|rule| !rule.adguard_domain.is_empty()) {
        bail!("unable to decompile binary AdGuard rules to rule-set.");
    }
    let path = output_path(source, output, DECOMPILE_DEFAULT_OUTPUT, ".srs", ".json");
    std::fs::write(&path, gojson::to_string_indent(&rule_set.to_json())).with_context(|| format!("open {path}"))?;
    Ok(())
}

/// The `-w` handling `format` and `upgrade` share.
fn emit(source: &str, content: &[u8], encoded: String, write: bool) -> Result<()> {
    if !write || source == "stdin" {
        std::io::stdout().write_all(format!("{encoded}\n").as_bytes())?;
        return Ok(());
    }
    if content == encoded.as_bytes() {
        return Ok(());
    }
    std::fs::write(source, encoded.as_bytes()).context("write output")?;
    eprintln!("{}", absolute(source).display());
    Ok(())
}

fn absolute(path: &str) -> PathBuf {
    std::path::absolute(path).unwrap_or_else(|_| PathBuf::from(path))
}

fn format(source: &str, write: bool) -> Result<()> {
    let content = read_source(source)?;
    let plain = parse_source(&content)?;
    emit(source, &content, gojson::to_string_indent(&plain.to_json()), write)
}

fn upgrade(source: &str, write: bool) -> Result<()> {
    let content = read_source(source)?;
    let mut plain = parse_source(&content)?;
    if plain.version != RULE_SET_VERSION_1 {
        eprintln!("INFO[0000] already up-to-date");
        return Ok(());
    }
    plain.options = plain.upgrade().map_err(|e| anyhow!(e))?;
    plain.version = RULE_SET_VERSION_CURRENT;
    emit(source, &content, gojson::to_string_indent(&plain.to_json()), write)
}

struct Entry {
    path: String,
    raw: Value,
    options: PlainRuleSetCompat,
}

fn read_entry(path: &str) -> Result<Entry> {
    let content = if path == "stdin" {
        let mut content = Vec::new();
        std::io::stdin().read_to_end(&mut content).with_context(|| format!("read config at {path}"))?;
        content
    } else {
        std::fs::read(path).with_context(|| format!("read config at {path}"))?
    };
    let raw = rb_config::parse_json_extended(&content).map_err(|e| anyhow!("decode config at {path}: {e}"))?;
    let options = PlainRuleSetCompat::from_value(raw.clone()).map_err(|e| anyhow!("decode config at {path}: {e}"))?;
    Ok(Entry { path: path.to_string(), raw, options })
}

/// badjson `mergeJSON` with appending enabled: objects merge key by key,
/// arrays append the source to the destination, and any other destination
/// value is kept.
fn merge_json(source: Value, destination: Value) -> Result<Value> {
    match destination {
        Value::Array(mut items) => {
            match source {
                Value::Array(more) => items.extend(more),
                other => items.push(other),
            }
            Ok(Value::Array(items))
        }
        Value::Object(mut object) => {
            let Value::Object(source) = source else {
                bail!("cannot merge json object into {}", go_type(&source));
            };
            for (key, value) in source {
                let value = match object.get(&key) {
                    Some(old) => merge_json(value, old.clone()).with_context(|| format!("merge object item {key}"))?,
                    None => value,
                };
                object.insert(key, value);
            }
            Ok(Value::Object(object))
        }
        other => Ok(other),
    }
}

fn go_type(value: &Value) -> &'static str {
    match value {
        Value::Null => "<nil>",
        Value::Bool(_) => "bool",
        Value::Number(_) => "json.Number",
        Value::String(_) => "string",
        Value::Array(_) => "badjson.JSONArray",
        Value::Object(_) => "*badjson.JSONObject",
    }
}

fn merge(output: &str, paths: &[String], directories: &[String]) -> Result<()> {
    let mut entries = Vec::new();
    for path in paths {
        entries.push(read_entry(path)?);
    }
    for directory in directories {
        let mut names = Vec::new();
        for entry in std::fs::read_dir(directory).with_context(|| format!("read rule-set directory at {directory}"))? {
            let entry = entry.with_context(|| format!("read rule-set directory at {directory}"))?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if !name.ends_with(".json") || entry.file_type().map(|kind| kind.is_dir()).unwrap_or(false) {
                continue;
            }
            names.push(name);
        }
        names.sort();
        for name in names {
            let path = Path::new(directory).join(name);
            entries.push(read_entry(&path.to_string_lossy())?);
        }
    }
    entries.sort_by(|a, b| a.path.cmp(&b.path));
    let merged = match entries.len() {
        0 => bail!("merge config: invalid argument"),
        1 => entries.remove(0).options,
        _ => {
            let version = entries.iter().map(|entry| entry.options.version).max().unwrap_or(0);
            let mut message: Option<Value> = None;
            for entry in entries {
                message = Some(match message {
                    None => entry.raw,
                    Some(destination) => {
                        merge_json(entry.raw, destination).with_context(|| format!("merge config at {}", entry.path))?
                    }
                });
            }
            let mut merged = PlainRuleSetCompat::from_value(message.unwrap_or(Value::Null))
                .map_err(|e| anyhow!("unmarshal merged config: {e}"))?;
            merged.version = version;
            merged
        }
    };
    let encoded = gojson::to_string_indent(&merged.to_json());
    if let Some(parent) = Path::new(output).parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    std::fs::write(output, encoded.as_bytes())?;
    eprintln!("{}", absolute(output).display());
    Ok(())
}

/// `M.ParseAddr`: an IP address, possibly in brackets or with a zone.
fn parse_addr(text: &str) -> Option<IpAddr> {
    let text = text.strip_prefix('[').and_then(|rest| rest.strip_suffix(']')).unwrap_or(text);
    let text = text.split('%').next().unwrap_or(text);
    text.parse().ok()
}

fn match_rule_set(source: &str, target: &str, mut format: String) -> Result<()> {
    let content = read_source(source).context("read rule-set")?;
    if format.is_empty() {
        match Path::new(source).extension().and_then(|ext| ext.to_str()) {
            Some("json") => format = FORMAT_SOURCE.into(),
            Some("srs") => format = FORMAT_BINARY.into(),
            _ => {}
        }
    }
    let rule_set = match format.as_str() {
        FORMAT_SOURCE => parse_source(&content)?,
        FORMAT_BINARY => srs::read(&content, false).map_err(|e| anyhow!(e.0))?,
        other => bail!("unknown rule-set format: {other}"),
    };
    let plain = rule_set.upgrade().map_err(|e| anyhow!(e))?;
    let address = parse_addr(target);
    let rule_sets = rb_rule::RuleSets::new();
    let mut context = rb_rule::Context::new(&rule_sets);
    // No network manager outside a box, as in sing-box's command.
    context.network_manager = false;
    for (index, options) in plain.rules.iter().enumerate() {
        let rule = rb_rule::compile_headless(options, &context)
            .map_err(|e| anyhow!("parse rule_set.rules.[{index}]: {}", e.0))?;
        let mut metadata = rb_rule::Metadata::default();
        match address {
            Some(ip) => metadata.destination_ip = Some(ip),
            None => metadata.domain = Some(target),
        }
        if rule.matches(&mut metadata) {
            eprintln!("match rules.[{index}]: {rule}");
        }
    }
    Ok(())
}

fn convert(source: &str, kind: &str, output: &str) -> Result<()> {
    let content = read_source(source)?;
    let rules = match kind {
        "adguard" => rb_config::adguard::to_options(&String::from_utf8_lossy(&content)).map_err(|e| anyhow!(e))?,
        "" => bail!("source type is required"),
        other => bail!("unsupported source type: {other}"),
    };
    let path = output_path(source, output, COMPILE_DEFAULT_OUTPUT, ".txt", ".srs");
    write_binary(&path, &PlainRuleSet { rules }, RULE_SET_VERSION_2)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_appends_rules_and_keeps_first_scalars() {
        let a: Value = serde_json::from_str(r#"{"version":1,"rules":[{"domain":"a"}]}"#).unwrap();
        let b: Value = serde_json::from_str(r#"{"version":3,"rules":[{"domain":"b"}]}"#).unwrap();
        let merged = merge_json(b, a).unwrap();
        assert_eq!(merged.to_string(), r#"{"version":1,"rules":[{"domain":"a"},{"domain":"b"}]}"#);
        assert!(merge_json(Value::Bool(true), serde_json::json!({})).is_err());
    }

    #[test]
    fn output_paths() {
        assert_eq!(output_path("a.json", COMPILE_DEFAULT_OUTPUT, COMPILE_DEFAULT_OUTPUT, ".json", ".srs"), "a.srs");
        assert_eq!(output_path("a", COMPILE_DEFAULT_OUTPUT, COMPILE_DEFAULT_OUTPUT, ".json", ".srs"), "a.srs");
        assert_eq!(output_path("a.json", "b", COMPILE_DEFAULT_OUTPUT, ".json", ".srs"), "b");
        assert_eq!(parse_addr("[::1]"), Some("::1".parse().unwrap()));
        assert_eq!(parse_addr("example.com"), None);
    }
}
