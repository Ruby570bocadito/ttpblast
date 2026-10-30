//! The alphabet turns telemetry events into symbols (ATT&CK techniques), the
//! way a genome is written with four letters. Rules are Sigma-like: plain
//! keys compare for equality, and `field|contains`, `field|startswith` and
//! `field|endswith` compare substrings. All values are lowercased.

use std::collections::HashMap;

use serde_json::Value;

use crate::events::Event;
use crate::i18n::{self, Lang};

pub const DEFAULT_JSON: &str = include_str!("../alphabet/default.json");

pub struct Symbol {
    pub code: String,
    pub technique: String,
    pub tactic: String,
    /// `"name": "…"`, or one per language: `"name": {"es": "…", "en": "…"}`.
    names: Vec<(String, String)>,
    rules: Vec<Rule>,
}

struct Rule(Vec<Condition>);

struct Condition {
    field: String,
    op: Op,
    values: Vec<String>,
}

#[derive(Clone, Copy)]
enum Op {
    Equals,
    Contains,
    StartsWith,
    EndsWith,
}

impl Condition {
    fn matches(&self, event: &Event) -> bool {
        let Some(actual) = event.get(&self.field) else {
            return false;
        };
        self.values.iter().any(|want| match self.op {
            Op::Equals => actual == want,
            Op::Contains => actual.contains(want.as_str()),
            Op::StartsWith => actual.starts_with(want.as_str()),
            Op::EndsWith => actual.ends_with(want.as_str()),
        })
    }
}

impl Symbol {
    fn matches(&self, event: &Event) -> bool {
        self.rules
            .iter()
            .any(|rule| rule.0.iter().all(|c| c.matches(event)))
    }

    /// The name in the output language, else in Spanish, else the first one.
    pub fn name(&self) -> &str {
        self.name_in(i18n::current())
    }

    pub fn name_in(&self, lang: Lang) -> &str {
        let find = |code: &str| self.names.iter().find(|(l, _)| l == code);
        find(lang.code())
            .or_else(|| find("es"))
            .or(self.names.first())
            .map_or("", |(_, name)| name.as_str())
    }
}

pub struct Alphabet {
    pub symbols: Vec<Symbol>,
    /// Lowercased code or technique ID -> symbol index.
    lookup: HashMap<String, usize>,
}

impl Alphabet {
    pub fn default_set() -> Self {
        Self::from_json(DEFAULT_JSON).expect("el alfabeto por defecto es válido")
    }

    pub fn from_json(text: &str) -> Result<Self, String> {
        let root: Value = serde_json::from_str(text)
            .map_err(|e| tr!("alfabeto no válido: {e}", "invalid alphabet: {e}"))?;
        let list = root
            .get("symbols")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                tr!(
                    "el alfabeto necesita una lista \"symbols\"",
                    "the alphabet needs a \"symbols\" list"
                )
            })?;

        let mut symbols = Vec::new();
        let mut lookup = HashMap::new();
        for (i, entry) in list.iter().enumerate() {
            let n = i + 1;
            let text_field = |key: &str| {
                entry
                    .get(key)
                    .and_then(Value::as_str)
                    .map(str::to_string)
                    .ok_or_else(|| {
                        tr!(
                            "símbolo {n}: falta \"{key}\"",
                            "symbol {n}: missing \"{key}\""
                        )
                    })
            };
            let code = text_field("code")?.to_uppercase();
            let technique = text_field("technique")?.to_uppercase();
            let rules = entry
                .get("rules")
                .and_then(Value::as_array)
                .ok_or_else(|| {
                    tr!(
                        "símbolo {code}: falta la lista \"rules\"",
                        "symbol {code}: missing the \"rules\" list"
                    )
                })?
                .iter()
                .map(parse_rule)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| tr!("símbolo {code}: {e}", "symbol {code}: {e}"))?;
            if rules.is_empty() {
                return Err(tr!(
                    "símbolo {code}: necesita al menos una regla",
                    "symbol {code}: needs at least one rule"
                ));
            }
            for key in [code.to_lowercase(), technique.to_lowercase()] {
                if lookup.insert(key.clone(), i).is_some() {
                    return Err(tr!(
                        "«{key}» aparece en más de un símbolo",
                        "«{key}» appears in more than one symbol"
                    ));
                }
            }
            let names = match entry.get("name") {
                Some(Value::String(name)) => vec![("es".to_string(), name.clone())],
                Some(Value::Object(by_lang)) => by_lang
                    .iter()
                    .filter_map(|(lang, name)| {
                        Some((lang.to_lowercase(), name.as_str()?.to_string()))
                    })
                    .collect(),
                _ => Vec::new(),
            };
            if names.is_empty() {
                return Err(tr!(
                    "símbolo {code}: falta \"name\" (un texto, o uno por idioma: {{\"es\": …, \"en\": …}})",
                    "symbol {code}: missing \"name\" (a text, or one per language: {{\"es\": …, \"en\": …}})"
                ));
            }
            symbols.push(Symbol {
                code,
                technique,
                tactic: text_field("tactic")?.to_lowercase(),
                names,
                rules,
            });
        }
        if symbols.is_empty() {
            return Err(tr!(
                "el alfabeto no tiene símbolos",
                "the alphabet has no symbols"
            ));
        }
        Ok(Alphabet { symbols, lookup })
    }

    /// First symbol whose rules match the event, if any.
    pub fn encode(&self, event: &Event) -> Option<usize> {
        self.symbols.iter().position(|s| s.matches(event))
    }

    /// Finds a symbol by its code (`PSH`) or technique ID (`T1059.001`).
    pub fn lookup(&self, token: &str) -> Option<usize> {
        self.lookup.get(&token.to_lowercase()).copied()
    }

    pub fn code(&self, symbol: usize) -> &str {
        &self.symbols[symbol].code
    }
}

fn parse_rule(value: &Value) -> Result<Rule, String> {
    let object = value.as_object().ok_or_else(|| {
        tr!(
            "cada regla debe ser un objeto",
            "each rule must be an object"
        )
    })?;
    let mut conditions = Vec::new();
    for (key, wanted) in object {
        let (field, op) = match key.split_once('|') {
            None => (key.as_str(), Op::Equals),
            Some((field, "contains")) => (field, Op::Contains),
            Some((field, "startswith")) => (field, Op::StartsWith),
            Some((field, "endswith")) => (field, Op::EndsWith),
            Some((_, modifier)) => {
                return Err(tr!(
                    "modificador desconocido: {modifier}",
                    "unknown modifier: {modifier}"
                ));
            }
        };
        let values = match wanted {
            Value::Array(items) => items.iter().map(value_text).collect::<Option<Vec<_>>>(),
            other => value_text(other).map(|v| vec![v]),
        }
        .filter(|v| !v.is_empty())
        .ok_or_else(|| tr!("valores no válidos en «{key}»", "invalid values in «{key}»"))?;
        conditions.push(Condition {
            field: field.to_string(),
            op,
            values,
        });
    }
    if conditions.is_empty() {
        return Err(tr!(
            "una regla vacía encajaría con todo",
            "an empty rule would match everything"
        ));
    }
    Ok(Rule(conditions))
}

fn value_text(value: &Value) -> Option<String> {
    match value {
        Value::String(s) => Some(s.to_lowercase()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(json: &str) -> Event {
        Event::from_json(&serde_json::from_str(json).unwrap()).unwrap()
    }

    #[test]
    fn default_alphabet_loads() {
        let a = Alphabet::default_set();
        assert!(a.symbols.len() >= 10);
        assert_eq!(a.lookup("psh"), a.lookup("T1059.001"));
    }

    #[test]
    fn first_matching_symbol_wins() {
        let a = Alphabet::default_set();
        // PowerShell started by Word is "user execution", not plain PowerShell.
        let from_word = event(
            r#"{"host":{"name":"h"},"event":{"action":"start"},"process":{"name":"powershell.exe","parent":{"name":"WINWORD.EXE"}}}"#,
        );
        assert_eq!(a.encode(&from_word).map(|s| a.code(s)), Some("UEX"));
        let plain = event(
            r#"{"host":{"name":"h"},"event":{"action":"start"},"process":{"name":"powershell.exe","parent":{"name":"explorer.exe"}}}"#,
        );
        assert_eq!(a.encode(&plain).map(|s| a.code(s)), Some("PSH"));
    }

    #[test]
    fn modifiers_and_numbers() {
        let a = Alphabet::default_set();
        let run_key = event(
            r#"{"host":{"name":"h"},"event":{"category":"registry"},"registry":{"path":"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\x"}}"#,
        );
        assert_eq!(a.encode(&run_key).map(|s| a.code(s)), Some("RUN"));
        let smb = event(
            r#"{"host":{"name":"h"},"event":{"category":"network"},"process":{"name":"powershell.exe"},"destination":{"port":445}}"#,
        );
        assert_eq!(a.encode(&smb).map(|s| a.code(s)), Some("SMB"));
        let browser = event(
            r#"{"host":{"name":"h"},"event":{"category":"network"},"process":{"name":"chrome.exe"},"destination":{"port":443}}"#,
        );
        assert_eq!(a.encode(&browser), None);
    }

    #[test]
    fn rejects_bad_alphabets() {
        assert!(Alphabet::from_json(r#"{"symbols": []}"#).is_err());
        let duplicated = r#"{"symbols": [
            {"code":"A","technique":"T1","tactic":"x","name":"a","rules":[{"k":"v"}]},
            {"code":"a","technique":"T2","tactic":"x","name":"b","rules":[{"k":"v"}]}]}"#;
        assert!(Alphabet::from_json(duplicated).is_err());
        let unknown_modifier = r#"{"symbols": [
            {"code":"A","technique":"T1","tactic":"x","name":"a","rules":[{"k|re":"v"}]}]}"#;
        assert!(Alphabet::from_json(unknown_modifier).is_err());
    }
}
