mod align;
mod alphabet;
mod events;
mod rng;
mod search;
mod sequence;
mod stats;
mod synth;
mod time;

use std::collections::HashMap;
use std::process::ExitCode;
use std::str::FromStr;

const USAGE: &str = "\
ttpblast: busca cadenas de ataque en telemetría de endpoint por alineamiento
local, al estilo BLAST, y dice cómo de significativo es cada parecido.

Uso:
  ttpblast search --query FICHERO --events FICHERO [opciones]
  ttpblast synth [--out DIR] [--days N] [--seed N]
  ttpblast encode --events FICHERO [--host NOMBRE] [--alphabet FICHERO]
  ttpblast alphabet [--alphabet FICHERO]

Opciones de search:
  --alphabet FICHERO   alfabeto JSON (por defecto, el incluido)
  --shuffles N         secuencias barajadas por host para calibrar (200)
  --block N            barajar en bloques de N símbolos (1)
  --null MODELO        modelo de las puntuaciones al azar: cola (exponencial,
                       como Karlin-Altschul) o gumbel (cola)
  --seed N             semilla del barajado (1)
  --evalue X           mostrar resultados con E <= X (10)
  --max-hits N         filas máximas en la tabla (10)
  --details N          resultados con el alineamiento detallado (3)
  --max-gap SEG        cortar en tramos tras SEG segundos sin actividad; 0 = no
                       cortar (3600)
  --maxspan SEG        ventana de la línea base exacta, en segundos (7200)
  --no-baseline        no ejecutar la línea base exacta

Opciones de synth:
  --out DIR            carpeta de salida (data/demo)
  --days N             días simulados, al menos 10 (14)
  --seed N             semilla (7)
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: &[String]) -> Result<(), String> {
    let Some((command, rest)) = args.split_first() else {
        print!("{USAGE}");
        return Ok(());
    };
    match command.as_str() {
        "search" => {
            let flags = Flags::parse(
                rest,
                &[
                    "query", "events", "alphabet", "shuffles", "block", "seed", "evalue",
                    "max-hits", "details", "maxspan", "max-gap", "null",
                ],
                &["no-baseline"],
            )?;
            search::run(&search::Options {
                query: flags.required("query")?.to_string(),
                events: flags.required("events")?.to_string(),
                alphabet: flags.text("alphabet").map(str::to_string),
                shuffles: flags.number("shuffles", 200)?,
                block: flags.number("block", 1)?,
                seed: flags.number("seed", 1)?,
                max_evalue: flags.number("evalue", 10.0)?,
                max_hits: flags.number("max-hits", 10)?,
                details: flags.number("details", 3)?,
                baseline: !flags.has("no-baseline"),
                maxspan: flags.number("maxspan", 7200)?,
                max_gap: flags.number("max-gap", 3600)?,
                null_model: search::NullModel::parse(flags.text("null").unwrap_or("cola"))?,
            })
        }
        "synth" => {
            let flags = Flags::parse(rest, &["out", "days", "seed"], &[])?;
            synth::run(&synth::Options {
                out: flags.text("out").unwrap_or("data/demo").to_string(),
                days: flags.number("days", 14)?,
                seed: flags.number("seed", 7)?,
            })
        }
        "encode" => {
            let flags = Flags::parse(rest, &["events", "host", "alphabet"], &[])?;
            let alphabet = search::load_alphabet(flags.text("alphabet"))?;
            let loaded = events::load_ndjson(flags.required("events")?)?;
            let wanted = flags.text("host").map(str::to_lowercase);
            for seq in sequence::build(&loaded.events, &alphabet) {
                if wanted.as_ref().is_some_and(|h| *h != seq.host) {
                    continue;
                }
                let codes: Vec<&str> = seq.symbols.iter().map(|&s| alphabet.code(s)).collect();
                println!("{:<16} {:>4}  {}", seq.host, codes.len(), codes.join(" "));
            }
            Ok(())
        }
        "alphabet" => {
            let flags = Flags::parse(rest, &["alphabet"], &[])?;
            let alphabet = search::load_alphabet(flags.text("alphabet"))?;
            println!("{:<5} {:<10} {:<20} nombre", "símb.", "técnica", "táctica");
            for s in &alphabet.symbols {
                println!(
                    "{:<5} {:<10} {:<20} {}",
                    s.code, s.technique, s.tactic, s.name
                );
            }
            Ok(())
        }
        "-h" | "--help" | "help" => {
            print!("{USAGE}");
            Ok(())
        }
        other => Err(format!(
            "orden desconocida «{other}». Usa `ttpblast --help`"
        )),
    }
}

struct Flags(HashMap<String, Option<String>>);

impl Flags {
    fn parse(args: &[String], with_value: &[&str], switches: &[&str]) -> Result<Self, String> {
        let mut map = HashMap::new();
        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            let name = arg
                .strip_prefix("--")
                .ok_or_else(|| format!("argumento inesperado «{arg}»"))?;
            if switches.contains(&name) {
                map.insert(name.to_string(), None);
            } else if with_value.contains(&name) {
                let value = iter
                    .next()
                    .ok_or_else(|| format!("--{name} necesita un valor"))?;
                map.insert(name.to_string(), Some(value.clone()));
            } else {
                return Err(format!(
                    "opción desconocida --{name}. Usa `ttpblast --help`"
                ));
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
        self.text(name).ok_or_else(|| format!("falta --{name}"))
    }

    fn number<T: FromStr>(&self, name: &str, default: T) -> Result<T, String> {
        match self.text(name) {
            None => Ok(default),
            Some(v) => v
                .parse()
                .map_err(|_| format!("--{name}: valor no válido «{v}»")),
        }
    }
}
