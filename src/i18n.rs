//! Output language. Spanish is the project's own language and the fallback;
//! English comes from `--lang en`, `TTPBLAST_LANG=en` or an English system
//! locale. Messages keep both versions side by side with `tr!`, so a change to
//! one is hard to miss in the other.

use std::sync::atomic::{AtomicBool, Ordering};

static ENGLISH: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lang {
    Es,
    En,
}

impl Lang {
    /// "es", "es_ES.UTF-8", "en-GB"... `None` for anything else.
    pub fn parse(text: &str) -> Option<Lang> {
        let text = text.trim().to_lowercase();
        if text.starts_with("es") {
            Some(Lang::Es)
        } else if text.starts_with("en") {
            Some(Lang::En)
        } else {
            None
        }
    }

    pub fn code(self) -> &'static str {
        match self {
            Lang::Es => "es",
            Lang::En => "en",
        }
    }
}

/// `format!` in the current language: `tr!("{n} hosts", "{n} hosts")`.
macro_rules! tr {
    ($es:literal, $en:literal $(,)?) => {
        if $crate::i18n::english() {
            format!($en)
        } else {
            format!($es)
        }
    };
    ($es:literal, $en:literal, $($arg:tt)*) => {
        if $crate::i18n::english() {
            format!($en, $($arg)*)
        } else {
            format!($es, $($arg)*)
        }
    };
}

/// The same for fixed text, without allocating.
pub fn t(es: &'static str, en: &'static str) -> &'static str {
    if english() { en } else { es }
}

pub fn set(lang: Lang) {
    ENGLISH.store(lang == Lang::En, Ordering::Relaxed);
}

pub fn current() -> Lang {
    if english() { Lang::En } else { Lang::Es }
}

pub fn english() -> bool {
    ENGLISH.load(Ordering::Relaxed)
}

/// `--lang` wins, then `TTPBLAST_LANG`, then the system locale. Spanish when
/// nothing says otherwise (or the locale is neither Spanish nor English).
pub fn detect(flag: Option<&str>) -> Result<Lang, String> {
    if let Some(flag) = flag {
        return Lang::parse(flag).ok_or_else(|| {
            format!("--lang: idioma desconocido «{flag}» (usa es o en) · unknown language (use es or en)")
        });
    }
    let from_env = std::env::var("TTPBLAST_LANG")
        .ok()
        .and_then(|v| Lang::parse(&v));
    Ok(from_env.or_else(system_locale).unwrap_or(Lang::Es))
}

/// LC_ALL, LC_MESSAGES or LANG, as POSIX tools read them; on Windows, if none
/// is set (Git Bash sets LANG, cmd and PowerShell do not), the display language.
fn system_locale() -> Option<Lang> {
    let posix = ["LC_ALL", "LC_MESSAGES", "LANG"]
        .iter()
        .filter_map(|key| std::env::var(key).ok())
        .find(|value| !value.is_empty());
    match posix {
        Some(value) => Lang::parse(&value),
        None => windows_ui_language(),
    }
}

#[cfg(windows)]
fn windows_ui_language() -> Option<Lang> {
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetUserDefaultUILanguage() -> u16;
    }
    // The primary language is the low 10 bits of a LANGID.
    // SAFETY: no arguments, no pointers; it only reads a user setting.
    match unsafe { GetUserDefaultUILanguage() } & 0x3ff {
        0x0a => Some(Lang::Es),
        0x09 => Some(Lang::En),
        _ => None,
    }
}

#[cfg(not(windows))]
fn windows_ui_language() -> Option<Lang> {
    None
}

/// 61234 -> "61.234" (es) or "61,234" (en).
pub fn count(n: usize) -> String {
    count_in(current(), n)
}

pub fn count_in(lang: Lang, n: usize) -> String {
    let separator = match lang {
        Lang::Es => '.',
        Lang::En => ',',
    };
    let digits = n.to_string();
    let mut out = String::new();
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(separator);
        }
        out.push(c);
    }
    out
}

/// 0.5 -> "0,50" (es) or "0.50" (en).
pub fn decimal(x: f64, decimals: usize) -> String {
    decimal_in(current(), x, decimals)
}

pub fn decimal_in(lang: Lang, x: f64, decimals: usize) -> String {
    let text = format!("{x:.decimals$}");
    match lang {
        Lang::Es => text.replace('.', ","),
        Lang::En => text,
    }
}

/// E-values and p-values: scientific notation when small, as BLAST does.
pub fn evalue(x: f64) -> String {
    evalue_in(current(), x)
}

pub fn evalue_in(lang: Lang, x: f64) -> String {
    if x >= 10.0 {
        format!("{x:.0}")
    } else if x >= 0.01 {
        decimal_in(lang, x, 2)
    } else {
        format!("{x:.1e}")
    }
}

/// "1 host" / "3 hosts". Spanish and English agree on when to use the plural
/// (only for one is it singular); the caller passes the words.
pub fn plural(n: usize, singular: &str, plural: &str) -> String {
    if n == 1 {
        format!("{n} {singular}")
    } else {
        format!("{} {plural}", count(n))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_locales() {
        assert_eq!(Lang::parse("es_ES.UTF-8"), Some(Lang::Es));
        assert_eq!(Lang::parse("EN-gb"), Some(Lang::En));
        assert_eq!(Lang::parse("C.UTF-8"), None);
        assert_eq!(Lang::parse("fr"), None);
    }

    #[test]
    fn numbers_follow_the_language() {
        assert_eq!(count_in(Lang::Es, 61_234), "61.234");
        assert_eq!(count_in(Lang::En, 61_234), "61,234");
        assert_eq!(count_in(Lang::Es, 999), "999");
        assert_eq!(decimal_in(Lang::Es, 0.5, 2), "0,50");
        assert_eq!(decimal_in(Lang::En, 0.5, 2), "0.50");
        assert_eq!(evalue_in(Lang::Es, 3.4e-8), "3.4e-8");
        assert_eq!(evalue_in(Lang::Es, 0.5), "0,50");
        assert_eq!(evalue_in(Lang::En, 2.594), "2.59");
        assert_eq!(evalue_in(Lang::En, 23.4), "23");
    }

    #[test]
    fn flag_beats_environment() {
        assert_eq!(detect(Some("en")).unwrap(), Lang::En);
        assert_eq!(detect(Some("es")).unwrap(), Lang::Es);
        assert!(detect(Some("klingon")).is_err());
    }
}
