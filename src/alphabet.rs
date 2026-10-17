//! The alphabet turns telemetry events into symbols (ATT&CK techniques), the
//! way a genome is written with four letters. Rules are Sigma-like: plain
//! keys compare for equality, and `field|contains`, `field|startswith` and
//! `field|endswith` compare substrings. All values are lowercased.

use std::collections::HashMap;

use serde_json::Value;

use crate::events::Event;

pub const DEFAULT_JSON: &str = include_str!("../alphabet/default.json");

pub struct Symbol {
    pub code: String,
    pub technique: String,
    pub tactic: String,
    pub name: String,
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
        let root: Value =
            serde_json::from_str(text).map_err(|e| format!("alfabeto no válido: {e}"))?;
        let list = root
            .get("symbols")
            .and_then(Value::as_array)
            .ok_or("el alfabeto necesita una lista \"symbols\"")?;

        let mut symbols = Vec::new();
        let mut lookup = HashMap::new();
        for (i, entry) in list.iter().enumerate() {
            let text_field = |key: &str| {
                entry
                    .get(key)
                    .and_then(Value::as_str)
                    .map(str::to_string)
                    .ok_or_else(|| format!("símbolo {}: falta \"{key}\"", i + 1))
            };
            let code = text_field("code")?.to_uppercase();
            let technique = text_field("technique")?.to_uppercase();
            let rules = entry
                .get("rules")
                .and_then(Value::as_array)
                .ok_or_else(|| format!("símbolo {code}: falta la lista \"rules\""))?
                .iter()
                .map(parse_rule)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| format!("símbolo {code}: {e}"))?;
            if rules.is_empty() {
                return Err(format!("símbolo {code}: necesita al menos una regla"));
            }
            for key in [code.to_lowercase(), technique.to_lowercase()] {
                if lookup.insert(key.clone(), i).is_some() {
                    return Err(format!("«{key}» aparece en más de un símbolo"));
                }
            }
            symbols.push(Symbol {
                code,
                technique,
                tactic: text_field("tactic")?.to_lowercase(),
                name: text_field("name")?,
                rules,
            });
        }
        if symbols.is_empty() {
            return Err("el alfabeto no tiene símbolos".into());
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
    let object = value.as_object().ok_or("cada regla debe ser un objeto")?;
    let mut conditions = Vec::new();
    for (key, wanted) in object {
        let (field, op) = match key.split_once('|') {
            None => (key.as_str(), Op::Equals),
            Some((field, "contains")) => (field, Op::Contains),
            Some((field, "startswith")) => (field, Op::StartsWith),
            Some((field, "endswith")) => (field, Op::EndsWith),
            Some((_, modifier)) => return Err(format!("modificador desconocido: {modifier}")),
        };
        let values = match wanted {
            Value::Array(items) => items.iter().map(value_text).collect::<Option<Vec<_>>>(),
            other => value_text(other).map(|v| vec![v]),
        }
        .filter(|v| !v.is_empty())
        .ok_or_else(|| format!("valores no válidos en «{key}»"))?;
        conditions.push(Condition {
            field: field.to_string(),
            op,
            values,
        });
    }
    if conditions.is_empty() {
        return Err("una regla vacía encajaría con todo".into());
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
