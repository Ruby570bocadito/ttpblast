//! `--html`: a self-contained report, one file with no network requests and
//! no external resources, that a hunter can open in any browser, keep with a
//! case or attach to a ticket. The page is a template with the search's JSON
//! inside. Telemetry is attacker-influenced text (a file path can say
//! anything), so the JSON is escaped to never close its script element, and
//! the page only ever writes it with `textContent`.

use std::fs;

use serde_json::Value;

const TEMPLATE: &str = include_str!("report.html");
const SLOT: &str = "\"@TTPBLAST_DATA@\"";

pub fn render(doc: &Value) -> String {
    let data = serde_json::to_string(doc).expect("un Value siempre se serializa");
    TEMPLATE.replacen(SLOT, &escape_for_script(&data), 1)
}

pub fn write(path: &str, doc: &Value) -> Result<(), String> {
    fs::write(path, render(doc)).map_err(|e| {
        tr!(
            "no se puede escribir {path}: {e}",
            "cannot write {path}: {e}"
        )
    })
}

/// `<`, `>` and `&` as JSON escapes: the JSON means the same, and neither
/// `</script>` nor `<!--` can appear inside the script element.
fn escape_for_script(json: &str) -> String {
    let mut out = String::with_capacity(json.len());
    for c in json.chars() {
        match c {
            '<' => out.push_str("\\u003c"),
            '>' => out.push_str("\\u003e"),
            '&' => out.push_str("\\u0026"),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn data_cannot_close_the_script() {
        let doc =
            json!({ "event": "cmd.exe crea c:\\x\\</script><script>alert(1)</script>.exe & <!--" });
        let html = render(&doc);
        let start = html.find("id=\"ttpblast-data\"").expect("bloque de datos");
        let block = &html[start..];
        let end = block.find("</script>").expect("cierre del bloque");
        let inside = &block[block.find('>').unwrap() + 1..end];
        assert!(!inside.contains('<') && !inside.contains('>'));
        // Still the same data once parsed.
        let parsed: Value = serde_json::from_str(inside).unwrap();
        assert_eq!(parsed, doc);
    }

    #[test]
    fn template_has_one_slot() {
        assert_eq!(TEMPLATE.matches(SLOT).count(), 1);
    }
}
