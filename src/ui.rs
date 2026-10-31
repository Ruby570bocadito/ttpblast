//! Terminal look: colours when stdout is a terminal (or with `--color
//! always`) and plain text otherwise, so pipes and files stay clean. Honours
//! NO_COLOR. Styles are named for what they mean, not for their colour, so the
//! whole tool speaks the same visual language: green is "identical", amber is
//! "similar", red is "far from chance".

use std::fmt::Display;
use std::io::{IsTerminal, Write};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use crate::i18n;

static COLOR: AtomicBool = AtomicBool::new(false);
static PROGRESS: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColorChoice {
    Auto,
    Always,
    Never,
}

impl ColorChoice {
    pub fn parse(text: &str) -> Result<Self, String> {
        match text {
            "auto" => Ok(ColorChoice::Auto),
            "always" | "siempre" => Ok(ColorChoice::Always),
            "never" | "nunca" => Ok(ColorChoice::Never),
            other => Err(tr!(
                "--color: valor desconocido «{other}» (usa auto, always o never)",
                "--color: unknown value «{other}» (use auto, always or never)"
            )),
        }
    }
}

pub fn init(choice: ColorChoice) {
    let allow_color = std::env::var_os("NO_COLOR").is_none_or(|v| v.is_empty());
    let on = match choice {
        ColorChoice::Always => {
            enable_vt();
            true
        }
        ColorChoice::Never => false,
        ColorChoice::Auto => allow_color && std::io::stdout().is_terminal() && enable_vt(),
    };
    COLOR.store(on, Ordering::Relaxed);

    // Progress and animation go to stderr, and only when stderr is a terminal,
    // so stdout, pipes, files and CI stay clean. NO_COLOR and `--color never`
    // silence them, like the colours.
    let animate = choice != ColorChoice::Never
        && (choice == ColorChoice::Always || allow_color)
        && std::io::stderr().is_terminal()
        && enable_vt_stderr();
    PROGRESS.store(animate, Ordering::Relaxed);
}

pub fn color() -> bool {
    COLOR.load(Ordering::Relaxed)
}

/// Whether to animate progress on stderr: stderr is a terminal and colours
/// are allowed, so stdout, pipes, files and CI stay clean.
pub fn progress() -> bool {
    PROGRESS.load(Ordering::Relaxed)
}

/// Windows consoles only interpret ANSI escapes once asked to.
#[cfg(windows)]
fn enable_vt() -> bool {
    type Handle = *mut core::ffi::c_void;
    const STD_OUTPUT_HANDLE: u32 = -11i32 as u32;
    const ENABLE_VIRTUAL_TERMINAL_PROCESSING: u32 = 0x0004;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetStdHandle(which: u32) -> Handle;
        fn GetConsoleMode(handle: Handle, mode: *mut u32) -> i32;
        fn SetConsoleMode(handle: Handle, mode: u32) -> i32;
    }
    // SAFETY: plain Win32 calls on this process's own stdout handle; `mode`
    // outlives the call that writes it.
    unsafe {
        let handle = GetStdHandle(STD_OUTPUT_HANDLE);
        if handle.is_null() || handle as isize == -1 {
            return false;
        }
        let mut mode = 0;
        if GetConsoleMode(handle, &mut mode) == 0 {
            return false;
        }
        mode & ENABLE_VIRTUAL_TERMINAL_PROCESSING != 0
            || SetConsoleMode(handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0
    }
}

#[cfg(not(windows))]
fn enable_vt() -> bool {
    true
}

/// The same as `enable_vt`, but for stderr, where the progress line is drawn.
/// stderr has its own console mode on Windows, so it must be enabled too, or
/// the escape codes would print literally.
#[cfg(windows)]
fn enable_vt_stderr() -> bool {
    type Handle = *mut core::ffi::c_void;
    const STD_ERROR_HANDLE: u32 = -12i32 as u32;
    const ENABLE_VIRTUAL_TERMINAL_PROCESSING: u32 = 0x0004;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetStdHandle(which: u32) -> Handle;
        fn GetConsoleMode(handle: Handle, mode: *mut u32) -> i32;
        fn SetConsoleMode(handle: Handle, mode: u32) -> i32;
    }
    // SAFETY: plain Win32 calls on this process's own stderr handle; `mode`
    // outlives the call that writes it.
    unsafe {
        let handle = GetStdHandle(STD_ERROR_HANDLE);
        if handle.is_null() || handle as isize == -1 {
            return false;
        }
        let mut mode = 0;
        if GetConsoleMode(handle, &mut mode) == 0 {
            return false;
        }
        mode & ENABLE_VIRTUAL_TERMINAL_PROCESSING != 0
            || SetConsoleMode(handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0
    }
}

#[cfg(not(windows))]
fn enable_vt_stderr() -> bool {
    true
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Style {
    /// The tool's own name and section titles.
    Brand,
    Bold,
    /// Secondary text: labels, explanations, what is only context.
    Quiet,
    /// Far from chance (E <= 0.01): what deserves a look first.
    Alert,
    /// Worth a second look (0.01 < E <= 1).
    Warn,
    /// An identical step, and good news in general.
    Same,
    /// A step substituted by another one of the same tactic.
    Similar,
    /// A step paired with one of another tactic.
    Different,
    /// Codes of the query, as typed by the user.
    Query,
}

impl Style {
    fn code(self) -> &'static str {
        match self {
            Style::Brand => "1;36",
            Style::Bold => "1",
            Style::Quiet => "2",
            Style::Alert => "1;31",
            Style::Warn => "33",
            Style::Same => "32",
            Style::Similar => "33",
            Style::Different => "31",
            Style::Query => "36",
        }
    }
}

/// The text with the style's escape codes, or as is without colours. Pad
/// before painting: escape codes have no width but `{:<n}` counts them.
pub fn paint(text: impl Display, style: Style) -> String {
    if color() {
        format!("\x1b[{}m{text}\x1b[0m", style.code())
    } else {
        text.to_string()
    }
}

/// How an E-value should look: alert, warning or quiet.
pub fn evalue_style(evalue: f64) -> Style {
    if evalue <= STRONG {
        Style::Alert
    } else if evalue <= WEAK {
        Style::Warn
    } else {
        Style::Quiet
    }
}

/// E-values at or below this are "far from chance".
pub const STRONG: f64 = 0.01;
/// And at or below this, worth a second look.
pub const WEAK: f64 = 1.0;

/// How far from chance, as a bar: one cell per order of magnitude below
/// E = 1, with eighths for the fraction, at most `width` cells. Always
/// `width` characters wide, so it lines up in a table.
pub fn signal_bar(evalue: f64, width: usize) -> String {
    const EIGHTHS: [char; 8] = [' ', '▏', '▎', '▍', '▌', '▋', '▊', '▉'];
    let level = (-evalue.max(f64::MIN_POSITIVE).log10()).clamp(0.0, width as f64);
    let eighths = (level * 8.0).round() as usize;
    let mut bar: String = "█".repeat(eighths / 8);
    if !eighths.is_multiple_of(8) {
        bar.push(EIGHTHS[eighths % 8]);
    }
    let used = bar.chars().count();
    bar.extend(std::iter::repeat_n(' ', width.saturating_sub(used)));
    bar
}

/// The logo: an attack chain aligned with the variant an attacker ran. It
/// is the whole idea of the tool in three lines.
pub fn logo() -> String {
    let query = [
        "UEX", "PSH", "C2W", "ITT", "RUN", "USR", "SID", "LSA", "SMB",
    ];
    let host = [
        "UEX", "CMD", "C2W", "ITT", "TSK", "USR", "RSD", "LSA", "WRM",
    ];
    let (mut top, mut mid, mut bottom) =
        (String::from("  "), String::from("  "), String::from("  "));
    for (q, h) in query.iter().zip(host) {
        let same = *q == h;
        top.push_str(&paint(q, Style::Query));
        top.push(' ');
        mid.push(' ');
        mid.push_str(&if same {
            paint("|", Style::Same)
        } else {
            paint("+", Style::Similar)
        });
        mid.push_str("  ");
        bottom.push_str(&paint(h, if same { Style::Same } else { Style::Similar }));
        bottom.push(' ');
    }
    format!(
        "{top}  {}\n{}\n{bottom}  {}\n",
        paint(
            i18n::t("← lo que buscas", "← what you look for"),
            Style::Quiet
        ),
        mid.trim_end(),
        paint(
            i18n::t("← lo que hizo el atacante", "← what the attacker did"),
            Style::Quiet
        ),
    )
}

/// Wraps plain text (no escape codes) at `width` columns, on spaces, with
/// `indent` before every line after the first.
pub fn wrap(text: &str, width: usize, indent: &str) -> String {
    let mut out = String::new();
    let mut column = 0;
    for word in text.split(' ').filter(|w| !w.is_empty()) {
        let len = word.chars().count();
        if column > 0 && column + 1 + len > width {
            out.push('\n');
            out.push_str(indent);
            column = indent.chars().count();
        } else if column > 0 {
            out.push(' ');
            column += 1;
        }
        out.push_str(word);
        column += len;
    }
    out
}

/// Levenshtein distance, for "did you mean…?" on mistyped commands and options.
pub fn distance(a: &str, b: &str) -> usize {
    let b: Vec<char> = b.chars().collect();
    let mut row: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.chars().enumerate() {
        let mut previous = row[0];
        row[0] = i + 1;
        for (j, cb) in b.iter().enumerate() {
            let substitution = previous + usize::from(ca != *cb);
            previous = row[j + 1];
            row[j + 1] = substitution.min(row[j] + 1).min(row[j + 1] + 1);
        }
    }
    row[b.len()]
}

/// The closest candidate, if it is close enough to be a typo (or the
/// Spanish word for it: "alfabeto" finds "alphabet").
pub fn suggest<'a>(typed: &str, candidates: &[&'a str]) -> Option<&'a str> {
    candidates
        .iter()
        .map(|c| (distance(typed, c), *c))
        .filter(|&(d, c)| d <= c.chars().count().div_ceil(2))
        .min()
        .map(|(_, c)| c)
}

/// What a progress line counts, so it can label itself (both languages kept
/// side by side here, like the rest of the UI).
#[derive(Clone, Copy)]
pub enum Kind {
    /// Hosts aligned, with the shuffles counted beside them: `search`, `demo`.
    Hosts,
    /// Queries run against the telemetry: `hunt`.
    Queries,
}

/// Shared between the workers (which bump the counters) and the single monitor
/// thread (which redraws the line). Only atomics cross the thread boundary.
struct Shared {
    kind: Kind,
    total: usize,
    done: AtomicUsize,
    shuffles: AtomicUsize,
    running: AtomicBool,
}

/// A live, one-line progress indicator on stderr: a Braille spinner and
/// running counts that show the work advancing. It draws only when
/// `progress()` is on (stderr is a terminal, colours allowed), so stdout,
/// pipes, files and CI never see it. All drawing happens on one monitor
/// thread, so it never interleaves with stdout or with itself; `finish`
/// (and `Drop`, as a backstop) clears the line before the real output begins.
/// When off, every method is a cheap no-op.
pub struct Progress {
    shared: Arc<Shared>,
    monitor: Mutex<Option<JoinHandle<()>>>,
    on: bool,
}

impl Progress {
    /// Starts a progress line counting `total` units of `kind`, if `enabled`
    /// and stderr allows it.
    pub fn start(enabled: bool, total: usize, kind: Kind) -> Progress {
        let on = enabled && progress();
        let shared = Arc::new(Shared {
            kind,
            total,
            done: AtomicUsize::new(0),
            shuffles: AtomicUsize::new(0),
            running: AtomicBool::new(on),
        });
        let monitor = if on {
            let shared = Arc::clone(&shared);
            Some(std::thread::spawn(move || run_monitor(shared)))
        } else {
            None
        };
        Progress {
            shared,
            monitor: Mutex::new(monitor),
            on,
        }
    }

    /// One more unit done, having run `shuffles` shuffles (0 when it counts
    /// something else). Lock-free; any worker thread may call it.
    pub fn tick(&self, shuffles: usize) {
        if !self.on {
            return;
        }
        self.shared.done.fetch_add(1, Ordering::Relaxed);
        self.shared.shuffles.fetch_add(shuffles, Ordering::Relaxed);
    }

    /// Stops the monitor and clears the line, so the real output starts on a
    /// clean row. Idempotent: only the first call (here or in `Drop`) acts.
    pub fn finish(&self) {
        if !self.on {
            return;
        }
        if let Ok(mut monitor) = self.monitor.lock()
            && let Some(handle) = monitor.take()
        {
            self.shared.running.store(false, Ordering::Relaxed);
            let _ = handle.join();
            let mut err = std::io::stderr();
            let _ = err.write_all(b"\r\x1b[2K");
            let _ = err.flush();
        }
    }
}

impl Drop for Progress {
    fn drop(&mut self) {
        self.finish();
    }
}

/// The monitor thread: redraw the line a few times a second until stopped.
/// It is the only writer to stderr while the work runs, so nothing interleaves.
fn run_monitor(shared: Arc<Shared>) {
    // A block that swells and shrinks: the same eighths as the signal bar, so
    // the spinner reads as the signal itself, breathing while the work runs.
    const FRAMES: [&str; 14] = [
        "▏", "▎", "▍", "▌", "▋", "▊", "▉", "█", "▉", "▊", "▋", "▌", "▍", "▎",
    ];
    let (brand, quiet) = (Style::Brand.code(), Style::Quiet.code());
    let mut err = std::io::stderr();
    let mut frame = 0usize;
    while shared.running.load(Ordering::Relaxed) {
        let spin = FRAMES[frame % FRAMES.len()];
        let done = shared.done.load(Ordering::Relaxed);
        let counts = match shared.kind {
            Kind::Hosts => tr!(
                "{}/{} hosts · {} barajados",
                "{}/{} hosts · {} shuffles",
                i18n::count(done),
                i18n::count(shared.total),
                i18n::count(shared.shuffles.load(Ordering::Relaxed))
            ),
            Kind::Queries => tr!(
                "{}/{} consultas",
                "{}/{} queries",
                i18n::count(done),
                i18n::count(shared.total)
            ),
        };
        let line = format!("\r\x1b[{brand}m{spin}\x1b[0m \x1b[{quiet}m{counts}\x1b[0m\x1b[K");
        let _ = err.write_all(line.as_bytes());
        let _ = err.flush();
        frame = frame.wrapping_add(1);
        std::thread::sleep(Duration::from_millis(90));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bar_has_fixed_width() {
        for e in [1e-12, 1.7e-6, 4.0e-4, 0.05, 1.0, 2.6, 300.0] {
            assert_eq!(signal_bar(e, 8).chars().count(), 8, "{e}");
        }
        assert_eq!(signal_bar(1e-3, 8).trim_end(), "███");
        assert_eq!(signal_bar(5.0, 8).trim_end(), "");
        assert_eq!(signal_bar(1e-30, 8), "████████");
    }

    #[test]
    fn no_escape_codes_without_color() {
        // Tests never call init(), so colours stay off.
        assert_eq!(paint("UEX", Style::Same), "UEX");
        assert!(!logo().contains('\x1b'));
    }

    #[test]
    fn wraps_on_spaces() {
        let text = wrap("uno dos tres cuatro cinco seis", 12, "  ");
        assert_eq!(text, "uno dos tres\n  cuatro\n  cinco seis");
        assert!(text.lines().all(|l| l.chars().count() <= 12));
    }

    #[test]
    fn suggestions() {
        let commands = ["search", "synth", "encode", "alphabet", "demo"];
        assert_eq!(suggest("serch", &commands), Some("search"));
        assert_eq!(suggest("alfabeto", &commands), Some("alphabet"));
        assert_eq!(suggest("xyz", &commands), None);
        assert_eq!(distance("kitten", "sitting"), 3);
    }
}
