//! ttpblast: BLAST for attack chains. Searches endpoint telemetry for
//! variants of a known chain by local alignment and says, with an E-value,
//! whether the resemblance is chance.

#[macro_use]
mod i18n;
mod align;
mod alphabet;
mod demo;
mod encode;
mod events;
mod evtx;
mod hunt;
mod library;
mod report;
mod rng;
mod search;
mod sequence;
mod stats;
mod synth;
mod sysmon;
mod time;
mod ui;
mod windows;

use std::collections::HashMap;
use std::io::IsTerminal;
use std::process::ExitCode;
use std::str::FromStr;

use i18n::t;
use ui::{ColorChoice, Style, paint};

const COMMANDS: [&str; 7] = [
    "search", "hunt", "demo", "synth", "encode", "alphabet", "help",
];

/// Options every search takes, from `search` and from `demo`.
const SEARCH_SETTINGS: [&str; 14] = [
    "alphabet",
    "shuffles",
    "block",
    "evalue",
    "max-hits",
    "details",
    "maxspan",
    "max-gap",
    "gap-open",
    "gap-extend",
    "extra-open",
    "extra-extend",
    "null",
    "threads",
];

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            let prefix = if ui::color() && std::io::stderr().is_terminal() {
                paint("error:", Style::Alert)
            } else {
                "error:".to_string()
            };
            eprintln!("{prefix} {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(mut args: Vec<String>) -> Result<(), String> {
    // Global options can go anywhere on the line. The language comes first,
    // so that every later message is already in it.
    let lang = take_global(&mut args, "lang")?;
    i18n::set(i18n::detect(lang.as_deref())?);
    let color = match take_global(&mut args, "color")? {
        Some(choice) => ColorChoice::parse(&choice)?,
        None => ColorChoice::Auto,
    };
    ui::init(color);

    let Some((command, rest)) = args.split_first() else {
        print!("{}", help());
        return Ok(());
    };
    if COMMANDS.contains(&command.as_str()) && rest.iter().any(|a| a == "--help" || a == "-h") {
        return command_help(command);
    }
    match command.as_str() {
        "search" => cmd_search(rest),
        "hunt" => cmd_hunt(rest),
        "demo" => cmd_demo(rest),
        "synth" => cmd_synth(rest),
        "encode" => cmd_encode(rest),
        "alphabet" => cmd_alphabet(rest),
        "help" => match rest.first() {
            Some(command) => command_help(command),
            None => {
                print!("{}", help());
                Ok(())
            }
        },
        "-h" | "--help" => {
            print!("{}", help());
            Ok(())
        }
        "-V" | "--version" => {
            println!("ttpblast {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        other => Err(unknown_command(other)),
    }
}

fn cmd_search(rest: &[String]) -> Result<(), String> {
    let mut with_value = vec!["query", "events", "seed", "html"];
    with_value.extend(SEARCH_SETTINGS);
    let flags = Flags::parse("search", rest, &with_value, &["no-baseline", "json"])?;
    let path = flags.required("query")?;
    let text = std::fs::read_to_string(path)
        .map_err(|e| tr!("no se puede leer {path}: {e}", "cannot read {path}: {e}"))?;
    let mut opts = search_settings(
        &flags,
        search::Options::new(path, &text, flags.required("events")?),
    )?;
    opts.seed = flags.number("seed", search::SEED)?;
    opts.json = flags.has("json");
    opts.html = flags.text("html").map(str::to_string);
    search::run(&opts).map(|_| ())
}

/// The search options shared by `search` and `demo`, over `base`.
fn search_settings(flags: &Flags, base: search::Options) -> Result<search::Options, String> {
    Ok(search::Options {
        alphabet: flags.text("alphabet").map(str::to_string),
        shuffles: flags.number("shuffles", base.shuffles)?,
        block: flags.number("block", base.block)?,
        max_evalue: flags.number("evalue", base.max_evalue)?,
        max_hits: flags.number("max-hits", base.max_hits)?,
        details: flags.number("details", base.details)?,
        baseline: !flags.has("no-baseline"),
        maxspan: flags.number("maxspan", base.maxspan)?,
        max_gap: flags.number("max-gap", base.max_gap)?,
        gap_open: flags.number("gap-open", base.gap_open)?,
        gap_extend: flags.number("gap-extend", base.gap_extend)?,
        extra_open: flags.number("extra-open", base.extra_open)?,
        extra_extend: flags.number("extra-extend", base.extra_extend)?,
        null_model: match flags.text("null") {
            Some(model) => search::NullModel::parse(model)?,
            None => base.null_model,
        },
        threads: flags.number("threads", base.threads)?,
        ..base
    })
}

fn cmd_hunt(rest: &[String]) -> Result<(), String> {
    let mut with_value = vec!["events", "queries", "html", "seed"];
    with_value.extend(SEARCH_SETTINGS);
    let flags = Flags::parse("hunt", rest, &with_value, &["json", "no-baseline"])?;
    let events = flags.required("events")?;
    let mut search = search_settings(&flags, search::Options::new("", "", events))?;
    search.seed = flags.number("seed", search::SEED)?;
    hunt::run(&hunt::Options {
        events: events.to_string(),
        queries: flags.text("queries").map(str::to_string),
        html: flags.text("html").map(str::to_string),
        json: flags.has("json"),
        search,
    })
}

fn cmd_demo(rest: &[String]) -> Result<(), String> {
    let mut with_value = vec!["out", "days", "seed", "padding"];
    with_value.extend(SEARCH_SETTINGS);
    let flags = Flags::parse("demo", rest, &with_value, &["no-html", "no-baseline"])?;
    demo::run(&demo::Options {
        synth: synth_options(&flags)?,
        html: !flags.has("no-html"),
        search: search_settings(&flags, search::Options::new("", "", ""))?,
    })
}

fn synth_options(flags: &Flags) -> Result<synth::Options, String> {
    Ok(synth::Options {
        out: flags.text("out").unwrap_or(synth::OUT).to_string(),
        days: flags.number("days", synth::DAYS)?,
        seed: flags.number("seed", synth::SEED)?,
        padding: flags.number("padding", 0)?,
    })
}

fn cmd_synth(rest: &[String]) -> Result<(), String> {
    let flags = Flags::parse("synth", rest, &["out", "days", "seed", "padding"], &[])?;
    synth::run(&synth_options(&flags)?)
}

fn cmd_encode(rest: &[String]) -> Result<(), String> {
    let flags = Flags::parse(
        "encode",
        rest,
        &["events", "host", "alphabet", "unmatched"],
        &[],
    )?;
    encode::run(&encode::Options {
        events: flags.required("events")?.to_string(),
        host: flags.text("host").map(str::to_string),
        alphabet: flags.text("alphabet").map(str::to_string),
        unmatched: flags.number("unmatched", 0)?,
    })
}

fn cmd_alphabet(rest: &[String]) -> Result<(), String> {
    let flags = Flags::parse("alphabet", rest, &["alphabet"], &[])?;
    let alphabet = search::load_alphabet(flags.text("alphabet"))?;
    println!(
        "{}",
        paint(
            format!(
                "{:<5} {:<10} {:<20} {}",
                t("símb.", "code"),
                t("técnica", "technique"),
                t("táctica", "tactic"),
                t("nombre", "name")
            ),
            Style::Quiet
        )
    );
    for s in &alphabet.symbols {
        println!(
            "{} {:<10} {} {}",
            paint(format!("{:<5}", s.code), Style::Query),
            s.technique,
            paint(format!("{:<20}", s.tactic), Style::Quiet),
            s.name()
        );
    }
    println!(
        "\n{}",
        paint(
            tr!(
                "{} símbolos. En una consulta vale el código (PSH) o el ID de técnica (T1059.001).",
                "{} symbols. A query takes the code (PSH) or the technique ID (T1059.001).",
                alphabet.symbols.len()
            ),
            Style::Quiet
        )
    );
    Ok(())
}

fn unknown_command(typed: &str) -> String {
    match ui::suggest(typed, &COMMANDS) {
        Some(guess) => tr!(
            "orden desconocida «{typed}»: ¿querías decir «{guess}»?",
            "unknown command «{typed}»: did you mean «{guess}»?"
        ),
        None => tr!(
            "orden desconocida «{typed}». Usa `ttpblast --help`",
            "unknown command «{typed}». See `ttpblast --help`"
        ),
    }
}

/// Removes `--name VALUE` or `--name=VALUE` from anywhere in `args`.
fn take_global(args: &mut Vec<String>, name: &str) -> Result<Option<String>, String> {
    let (flag, prefix) = (format!("--{name}"), format!("--{name}="));
    let mut found = None;
    let mut i = 0;
    while i < args.len() {
        if args[i] == flag {
            if i + 1 == args.len() {
                return Err(format!("{flag} necesita un valor · {flag} needs a value"));
            }
            found = Some(args.remove(i + 1));
            args.remove(i);
        } else if let Some(value) = args[i].strip_prefix(&prefix) {
            found = Some(value.to_string());
            args.remove(i);
        } else {
            i += 1;
        }
    }
    Ok(found)
}

struct Flags(HashMap<String, Option<String>>);

impl Flags {
    /// `--name value`, `--name=value` and `--switch`, nothing else.
    fn parse(
        command: &str,
        args: &[String],
        with_value: &[&str],
        switches: &[&str],
    ) -> Result<Self, String> {
        let mut map = HashMap::new();
        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            let Some(flag) = arg.strip_prefix("--") else {
                return Err(tr!(
                    "argumento inesperado «{arg}». Usa `ttpblast {command} --help`",
                    "unexpected argument «{arg}». See `ttpblast {command} --help`"
                ));
            };
            let (name, inline) = match flag.split_once('=') {
                Some((name, value)) => (name, Some(value.to_string())),
                None => (flag, None),
            };
            if switches.contains(&name) && inline.is_none() {
                map.insert(name.to_string(), None);
            } else if with_value.contains(&name) {
                let value = match inline {
                    Some(value) => value,
                    None => iter.next().cloned().ok_or_else(|| {
                        tr!("--{name} necesita un valor", "--{name} needs a value")
                    })?,
                };
                map.insert(name.to_string(), Some(value));
            } else {
                let known: Vec<&str> = with_value.iter().chain(switches).copied().collect();
                return Err(match ui::suggest(name, &known) {
                    Some(guess) => tr!(
                        "opción desconocida --{name}: ¿querías decir --{guess}?",
                        "unknown option --{name}: did you mean --{guess}?"
                    ),
                    None => tr!(
                        "opción desconocida --{name}. Usa `ttpblast {command} --help`",
                        "unknown option --{name}. See `ttpblast {command} --help`"
                    ),
                });
            }
        }
        Ok(Flags(map))
    }

    fn has(&self, name: &str) -> bool {
        self.0.contains_key(name)
    }

    fn text(&self, name: &str) -> Option<&str> {
        self.0.get(name).and_then(|v| v.as_deref())
    }

    fn required(&self, name: &str) -> Result<&str, String> {
        self.text(name)
            .ok_or_else(|| tr!("falta --{name}", "missing --{name}"))
    }

    fn number<T: FromStr>(&self, name: &str, default: T) -> Result<T, String> {
        match self.text(name) {
            None => Ok(default),
            Some(v) => v.parse().map_err(|_| {
                tr!(
                    "--{name}: valor no válido «{v}»",
                    "--{name}: invalid value «{v}»"
                )
            }),
        }
    }
}

// ------------------------------------------------------------------- help

fn heading(text: &str) -> String {
    paint(text, Style::Bold)
}

fn help() -> String {
    let logo = ui::logo();
    let name = paint("ttpblast", Style::Brand);
    let version = env!("CARGO_PKG_VERSION");
    if i18n::english() {
        format!(
            "\n{logo}
{name} {version} · BLAST for attack chains
Searches your machines' telemetry for variants of a known attack chain and
tells you, with an E-value, whether the resemblance is chance.

{start}
  ttpblast demo              guided demo: hides four chains in synthetic
                             telemetry, finds them and grades itself (seconds)

{commands}
  search      search the telemetry for an attack chain
  hunt        every query in the library at once: one verdict per query
  demo        the guided demo
  synth       generate synthetic telemetry with hidden attack chains
  encode      each host's \"genome\": its events written as symbols
  alphabet    the available symbols (MITRE ATT&CK techniques)
  help CMD    a command's options (or ttpblast CMD --help)

{global}
  --lang es|en               output language (or TTPBLAST_LANG; otherwise the
                             system's)
  --color auto|always|never  colours; auto: only on a terminal, without NO_COLOR
  --version                  version

{examples}
  ttpblast search --query queries/phishing-lateral.txt --events data/demo/events.ndjson
  ttpblast search ... --html report.html     visual report for the browser
  ttpblast search ... --json                 for scripts and other tools
  ttpblast hunt --events logs/                 every query, over a folder of .evtx files
  ttpblast encode --events data/sysmon/events.ndjson --unmatched 15

More at https://github.com/Ruby570bocadito/ttpblast
",
            start = heading("Start here"),
            commands = heading("Commands"),
            global = heading("Global options"),
            examples = heading("Examples"),
        )
    } else {
        format!(
            "\n{logo}
{name} {version} · BLAST para cadenas de ataque
Busca variantes de una cadena de ataque conocida en la telemetría de tus
equipos y te dice, con un E-value, si el parecido es casualidad.

{start}
  ttpblast demo              demo guiada: esconde cuatro cadenas en telemetría
                             sintética, las busca y se pone nota (segundos)

{commands}
  search      busca una cadena de ataque en la telemetría
  hunt        toda la biblioteca de consultas de una vez: un veredicto por consulta
  demo        la demo guiada
  synth       genera telemetría sintética con cadenas de ataque escondidas
  encode      el «genoma» de cada host: sus eventos convertidos en símbolos
  alphabet    los símbolos disponibles (técnicas de MITRE ATT&CK)
  help ORDEN  las opciones de una orden (o ttpblast ORDEN --help)

{global}
  --lang es|en               idioma de la salida (o TTPBLAST_LANG; si no, el
                             del sistema)
  --color auto|always|never  colores; auto: solo en una terminal y sin NO_COLOR
  --version                  versión

{examples}
  ttpblast search --query queries/phishing-lateral.txt --events data/demo/events.ndjson
  ttpblast search ... --html informe.html    informe visual para el navegador
  ttpblast search ... --json                 para scripts y otras herramientas
  ttpblast hunt --events registros/           todas las consultas, sobre una carpeta de .evtx
  ttpblast encode --events data/sysmon/events.ndjson --unmatched 15

Más en https://github.com/Ruby570bocadito/ttpblast
",
            start = heading("Empieza por aquí"),
            commands = heading("Órdenes"),
            global = heading("Opciones globales"),
            examples = heading("Ejemplos"),
        )
    }
}

fn command_help(command: &str) -> Result<(), String> {
    let title = |text: &str| {
        format!(
            "{} · {text}\n",
            paint(format!("ttpblast {command}"), Style::Brand)
        )
    };
    let text = match (command, i18n::english()) {
        ("search", false) => format!(
            "{}
{}
  ttpblast search --query FICHERO --events FICHERO [opciones]

{}
  --query FICHERO       la cadena: códigos de símbolo o IDs de técnica, en orden
                        (ejemplos en queries/; `ttpblast alphabet` lista los códigos)
  --events RUTA         telemetría: .evtx, NDJSON (ECS, Sysmon exportado,
                        Winlogbeat) o una carpeta con varios
  --alphabet FICHERO    alfabeto JSON (por defecto, el incluido)

{}
  --evalue X            resultados con E <= X ({})
  --max-hits N          filas máximas en la tabla ({})
  --details N           resultados con el alineamiento detallado ({})
  --json                resultados en JSON, para scripts y otras herramientas
  --html FICHERO        además, un informe HTML autocontenido
  --no-baseline         sin la línea base exacta
  --maxspan SEG         ventana de la línea base exacta, en segundos ({})

{}
  --max-gap SEG         cortar en tramos tras SEG segundos sin actividad;
                        0 = no cortar ({})
  --gap-open N          coste de un paso de la consulta que falta en el host ({})
  --gap-extend N        coste de cada otro paso que falta seguido ({})
  --extra-open N        coste de un paso de más en el host ({})
  --extra-extend N      coste de cada otro paso de más seguido ({})

{}
  --shuffles N          secuencias barajadas por host para calibrar ({})
  --block N             barajar en bloques de N símbolos; la región del mejor
                        alineamiento, siempre símbolo a símbolo ({})
  --null MODELO         cola (exponencial, como Karlin-Altschul) o gumbel (cola)
  --seed N              semilla del barajado ({})
  --threads N           hilos; 0 = uno por núcleo (0)
",
            title("busca una cadena de ataque en la telemetría"),
            heading("Uso"),
            heading("Entrada"),
            heading("Salida"),
            search::MAX_EVALUE,
            search::MAX_HITS,
            search::DETAILS,
            search::MAXSPAN,
            heading("Alineamiento"),
            search::MAX_GAP,
            align::GAP_OPEN,
            align::GAP_EXTEND,
            align::EXTRA_OPEN,
            align::EXTRA_EXTEND,
            heading("Significación"),
            search::SHUFFLES,
            search::BLOCK,
            search::SEED,
        ),
        ("search", true) => format!(
            "{}
{}
  ttpblast search --query FILE --events FILE [options]

{}
  --query FILE          the chain: symbol codes or technique IDs, in order
                        (examples in queries/; `ttpblast alphabet` lists the codes)
  --events PATH         telemetry: .evtx, NDJSON (ECS, exported Sysmon,
                        Winlogbeat) or a folder with several
  --alphabet FILE       JSON alphabet (the built-in one by default)

{}
  --evalue X            hits with E <= X ({})
  --max-hits N          most rows in the table ({})
  --details N           hits shown with their full alignment ({})
  --json                results as JSON, for scripts and other tools
  --html FILE           also a self-contained HTML report
  --no-baseline         skip the exact baseline
  --maxspan SECS        window of the exact baseline, in seconds ({})

{}
  --max-gap SECS        cut into stretches after SECS seconds without activity;
                        0 = no cuts ({})
  --gap-open N          cost of a query step missing from the host ({})
  --gap-extend N        cost of each further missing step in a row ({})
  --extra-open N        cost of an extra step on the host ({})
  --extra-extend N      cost of each further extra step in a row ({})

{}
  --shuffles N          shuffled sequences per host to calibrate ({})
  --block N             shuffle in blocks of N symbols; the region of the best
                        alignment, always symbol by symbol ({})
  --null MODEL          tail (exponential, as Karlin-Altschul) or gumbel (tail)
  --seed N              shuffle seed ({})
  --threads N           threads; 0 = one per core (0)
",
            title("search the telemetry for an attack chain"),
            heading("Usage"),
            heading("Input"),
            heading("Output"),
            search::MAX_EVALUE,
            search::MAX_HITS,
            search::DETAILS,
            search::MAXSPAN,
            heading("Alignment"),
            search::MAX_GAP,
            align::GAP_OPEN,
            align::GAP_EXTEND,
            align::EXTRA_OPEN,
            align::EXTRA_EXTEND,
            heading("Significance"),
            search::SHUFFLES,
            search::BLOCK,
            search::SEED,
        ),
        ("hunt", false) => format!(
            "{}
{}
  ttpblast hunt --events FICHERO|CARPETA [opciones]

Pasa todas las consultas de la biblioteca (o de una carpeta) por la misma
telemetría, leída una sola vez, y da un veredicto por consulta. Los hosts que
señalan varias consultas salen aparte: es lo primero que conviene mirar.

{}
  --events RUTA        telemetría: .evtx, NDJSON o una carpeta con varios
  --queries CARPETA    consultas (.txt) de esa carpeta en vez de la biblioteca
                       incluida ({} consultas)
  --html CARPETA       además, un informe HTML por consulta en esa carpeta
  --json               resultados en JSON, para scripts y otras herramientas
  --shuffles N, --block N, --null MODELO, --max-gap SEG, --gap-open N,
  --extra-open N, --seed N, --threads N…: como en `ttpblast search`
",
            title("toda la biblioteca de consultas de una vez"),
            heading("Uso"),
            heading("Opciones"),
            library::LIBRARY.len(),
        ),
        ("hunt", true) => format!(
            "{}
{}
  ttpblast hunt --events FILE|FOLDER [options]

Runs every query in the library (or in a folder) over the same telemetry,
read once, and gives one verdict per query. Hosts that several queries point
at get their own line: that is where to look first.

{}
  --events PATH        telemetry: .evtx, NDJSON or a folder with several
  --queries FOLDER     the queries (.txt) in that folder instead of the
                       built-in library ({} queries)
  --html FOLDER        also one HTML report per query in that folder
  --json               results as JSON, for scripts and other tools
  --shuffles N, --block N, --null MODEL, --max-gap SECS, --gap-open N,
  --extra-open N, --seed N, --threads N…: as in `ttpblast search`
",
            title("every query in the library at once"),
            heading("Usage"),
            heading("Options"),
            library::LIBRARY.len(),
        ),
        ("demo", false) => format!(
            "{}
{}
  ttpblast demo [opciones]

Genera telemetría sintética con cuatro cadenas de ataque escondidas, busca
dos consultas (incluidas en el binario: no hace falta nada más) y compara lo
encontrado con la verdad.

{}
  --out DIR          carpeta para la telemetría y los informes ({})
  --days N           días simulados, al menos 10 ({})
  --seed N           semilla de la telemetría ({})
  --padding N        comandos de relleno entre cada dos pasos de cada cadena,
                     para ver cuánto cuesta esconderla (0)
  --no-html          sin informes HTML
  --details N, --shuffles N, --block N, --null MODELO, --max-gap SEG,
  --gap-open N, --extra-open N, --threads N…: como en `ttpblast search`
",
            title("la demo guiada"),
            heading("Uso"),
            heading("Opciones"),
            synth::OUT,
            synth::DAYS,
            synth::SEED,
        ),
        ("demo", true) => format!(
            "{}
{}
  ttpblast demo [options]

Generates synthetic telemetry with four hidden attack chains, runs two
queries (built into the binary: nothing else needed) and compares what it
found with the truth.

{}
  --out DIR          folder for the telemetry and the reports ({})
  --days N           simulated days, at least 10 ({})
  --seed N           telemetry seed ({})
  --padding N        padding commands between every two steps of each chain,
                     to see how much it takes to hide it (0)
  --no-html          no HTML reports
  --details N, --shuffles N, --block N, --null MODEL, --max-gap SECS,
  --gap-open N, --extra-open N, --threads N…: as in `ttpblast search`
",
            title("the guided demo"),
            heading("Usage"),
            heading("Options"),
            synth::OUT,
            synth::DAYS,
            synth::SEED,
        ),
        ("synth", false) => format!(
            "{}
{}
  ttpblast synth [--out DIR] [--days N] [--seed N] [--padding N]

  --out DIR          carpeta de salida: events.ndjson y truth.json ({})
  --days N           días simulados, al menos 10 ({})
  --seed N           semilla ({})
  --padding N        comandos de relleno entre cada dos pasos de cada cadena (0)

Todo es inventado: dominios de ejemplo (*.example.*) y direcciones privadas.
",
            title("telemetría sintética con cadenas de ataque escondidas"),
            heading("Uso"),
            synth::OUT,
            synth::DAYS,
            synth::SEED,
        ),
        ("synth", true) => format!(
            "{}
{}
  ttpblast synth [--out DIR] [--days N] [--seed N] [--padding N]

  --out DIR          output folder: events.ndjson and truth.json ({})
  --days N           simulated days, at least 10 ({})
  --seed N           seed ({})
  --padding N        padding commands between every two steps of each chain (0)

All of it is made up: example domains (*.example.*) and private addresses.
",
            title("synthetic telemetry with hidden attack chains"),
            heading("Usage"),
            synth::OUT,
            synth::DAYS,
            synth::SEED,
        ),
        ("encode", false) => format!(
            "{}
{}
  ttpblast encode --events FICHERO [--host NOMBRE] [--unmatched N] [--alphabet FICHERO]

  --events FICHERO     telemetría NDJSON
  --host NOMBRE        solo ese host
  --unmatched N        los N tipos de evento sin símbolo más frecuentes: lo que
                       el alfabeto no está viendo
  --alphabet FICHERO   alfabeto JSON (por defecto, el incluido)
",
            title("el «genoma» de cada host: sus eventos como símbolos"),
            heading("Uso"),
        ),
        ("encode", true) => format!(
            "{}
{}
  ttpblast encode --events FILE [--host NAME] [--unmatched N] [--alphabet FILE]

  --events FILE        NDJSON telemetry
  --host NAME          only that host
  --unmatched N        the N most frequent kinds of events without a symbol:
                       what the alphabet is not seeing
  --alphabet FILE      JSON alphabet (the built-in one by default)
",
            title("each host's \"genome\": its events as symbols"),
            heading("Usage"),
        ),
        ("alphabet", false) => format!(
            "{}
{}
  ttpblast alphabet [--alphabet FICHERO]

Cada símbolo es una técnica de MITRE ATT&CK con reglas al estilo Sigma. En una
consulta vale el código (PSH) o el ID de técnica (T1059.001).
",
            title("los símbolos disponibles"),
            heading("Uso"),
        ),
        ("alphabet", true) => format!(
            "{}
{}
  ttpblast alphabet [--alphabet FILE]

Each symbol is a MITRE ATT&CK technique with Sigma-style rules. A query takes
the code (PSH) or the technique ID (T1059.001).
",
            title("the available symbols"),
            heading("Usage"),
        ),
        ("help", _) => help(),
        (other, _) => return Err(unknown_command(other)),
    };
    print!("{text}");
    Ok(())
}
