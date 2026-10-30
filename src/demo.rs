//! `ttpblast demo`: a guided tour. It hides four attack chains in two weeks
//! of synthetic telemetry, looks for them the way an analyst would (with a
//! query, without knowing where they are) and grades the result against the
//! truth. It needs nothing but the binary: the queries are built in.

use crate::i18n::{self, t};
use crate::search::{self, Summary};
use crate::synth::{self, Truth};
use crate::ui::{self, Style, paint};

pub const PHISHING: Query = Query {
    stem: "phishing-lateral",
    path: "queries/phishing-lateral.txt",
    text: include_str!("../queries/phishing-lateral.txt"),
};
pub const EXFILTRATION: Query = Query {
    stem: "exfiltracion",
    path: "queries/exfiltracion.txt",
    text: include_str!("../queries/exfiltracion.txt"),
};

pub struct Query {
    pub stem: &'static str,
    pub path: &'static str,
    pub text: &'static str,
}

pub struct Options {
    pub synth: synth::Options,
    /// Write an HTML report for each search next to the telemetry.
    pub html: bool,
    /// Search settings shared by both searches (query and events are set here).
    pub search: search::Options,
}

pub fn run(opts: &Options) -> Result<(), String> {
    println!(
        "{} {}\n{}",
        paint("ttpblast demo", Style::Brand),
        paint(
            t(
                "· BLAST para cadenas de ataque",
                "· BLAST for attack chains"
            ),
            Style::Quiet
        ),
        t(
            "Escondo cuatro cadenas de ataque en dos semanas de telemetría inventada y las\n\
             busco como lo haría un analista: con una consulta y sin saber dónde están.",
            "I hide four attack chains in two weeks of made-up telemetry and look for them\n\
             the way an analyst would: with a query, and without knowing where they are."
        )
    );

    section(1, t("La telemetría", "The telemetry"));
    let generated = synth::generate(&opts.synth)?;
    println!(
        "{}",
        tr!(
            "{} hosts Windows durante {} días: {} eventos → {}",
            "{} Windows hosts over {} days: {} events → {}",
            generated.hosts,
            opts.synth.days,
            i18n::count(generated.events),
            generated.events_path
        )
    );
    println!(
        "{}",
        t(
            "Rutina de oficina, tres administradores que hacen descubrimiento a diario, un\n\
             servidor que comprime y sube copias cada noche y, escondidas, estas cadenas:",
            "Office routine, three admins who run discovery every day, a server that\n\
             compresses and uploads backups every night and, hidden in it, these chains:"
        )
    );
    synth::print_truth(&generated.truth);
    if opts.synth.padding > 0 {
        println!(
            "{}",
            tr!(
                "Con {} comandos de relleno entre cada dos pasos de cada cadena.",
                "With {} padding commands between every two steps of each chain.",
                opts.synth.padding
            )
        );
    }
    println!(
        "{}",
        paint(
            tr!(
                "(la verdad queda en {}, para comprobar el resultado)",
                "(the truth is in {}, to check the result)",
                generated.truth_path
            ),
            Style::Quiet
        )
    );

    section(
        2,
        t(
            "Búsqueda: documento malicioso → movimiento lateral",
            "Search: malicious document → lateral movement",
        ),
    );
    let phishing = search_with(opts, &PHISHING, &generated.events_path, opts.search.details)?;

    section(
        3,
        t(
            "Búsqueda: reconocimiento → exfiltración",
            "Search: reconnaissance → exfiltration",
        ),
    );
    let exfiltration = search_with(
        opts,
        &EXFILTRATION,
        &generated.events_path,
        opts.search.details.min(1),
    )?;
    if let Some(backup) = exfiltration
        .ranking
        .iter()
        .find(|r| r.host.starts_with("srv-backup") && r.evalue > ui::WEAK)
    {
        // Its resemblance can beat hosts that made the table: say so.
        let beaten = exfiltration
            .ranking
            .get(1)
            .filter(|second| second.evalue <= search::MAX_EVALUE && backup.score > second.score);
        let resemblance = match beaten {
            Some(second) => tr!(
                "se parece a la consulta (puntuación {}) más que {}, el segundo de la tabla,",
                "resembles the query (score {}) more than {}, second in the table,",
                backup.score,
                second.host
            ),
            None => tr!(
                "se parece a la consulta (puntuación {}),",
                "resembles the query (score {}),",
                backup.score
            ),
        };
        let note = tr!(
            "Fíjate en {}: {resemblance} pero comprime y sube datos todas las noches. Para \
             ese host es lo normal (E = {}): cada host se compara con su propia rutina.",
            "Look at {}: it {resemblance} but it compresses and uploads data every night. \
             For that host it is routine (E = {}): each host is compared with its own routine.",
            backup.host,
            i18n::evalue(backup.evalue)
        );
        println!("{} {}", paint("→", Style::Brand), ui::wrap(&note, 76, "  "));
    }

    section(4, t("Nota frente a la verdad", "Grade against the truth"));
    let results = [(&PHISHING, &phishing), (&EXFILTRATION, &exfiltration)];
    let mut found = 0;
    let mut exact = 0;
    for chain in &generated.truth {
        let Some((_, summary)) = results.iter().find(|(q, _)| q.stem == chain.query) else {
            continue;
        };
        found += usize::from(grade(chain, summary));
        exact += usize::from(
            summary
                .baseline
                .as_ref()
                .is_some_and(|hosts| hosts.iter().any(|h| h == chain.host)),
        );
    }
    let total = generated.truth.len();
    println!(
        "  {}",
        tr!(
            "{found} de {total} cadenas con E ≤ {}. La búsqueda exacta habría encontrado {exact}.",
            "{found} of {total} chains with E ≤ {}. The exact search would have found {exact}.",
            i18n::decimal(ui::STRONG, 2)
        )
    );
    if opts.synth.padding > 0 && !opts.search.mask && found < total {
        let note = t(
            "El relleno las esconde: cada comando intercalado abre un hueco. Prueba otra vez \
             con --mask, que se salta gratis la rutina de cada host.",
            "The padding hides them: each command slipped in opens a gap. Try again with \
             --mask, which skips each host's routine for free.",
        );
        println!("{} {}", paint("→", Style::Brand), ui::wrap(note, 76, "  "));
    }

    if opts.html {
        println!(
            "\n{} {}",
            paint(t("Informes visuales:", "Visual reports:"), Style::Bold),
            [&PHISHING, &EXFILTRATION]
                .iter()
                .map(|q| report_path(&opts.synth.out, q))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    println!(
        "{} {}",
        paint(t("Siguiente paso:", "Next step:"), Style::Bold),
        t(
            "tu propia telemetría (README, «Con tu propia telemetría»).",
            "your own telemetry (README, «With your own telemetry»)."
        )
    );
    Ok(())
}

fn search_with(
    opts: &Options,
    query: &Query,
    events: &str,
    details: usize,
) -> Result<Summary, String> {
    let html = opts.html.then(|| report_path(&opts.synth.out, query));
    let mask = match (opts.search.mask, opts.search.routine) {
        (false, _) => String::new(),
        (true, search::ROUTINE) => " --mask".to_string(),
        (true, routine) => format!(" --mask --routine {routine}"),
    };
    println!(
        "{}\n",
        paint(
            format!(
                "$ ttpblast search --query {} --events {events}{mask}{}{}",
                query.path,
                if details == search::DETAILS {
                    String::new()
                } else {
                    format!(" --details {details}")
                },
                html.as_ref()
                    .map(|path| format!(" --html {path}"))
                    .unwrap_or_default()
            ),
            Style::Quiet
        )
    );
    let settings = search::Options {
        query_label: query.path.to_string(),
        query_text: query.text.to_string(),
        events: events.to_string(),
        details,
        html,
        ..opts.search.clone()
    };
    search::run(&settings)
}

fn report_path(dir: &str, query: &Query) -> String {
    synth::join(
        dir,
        &format!("{}-{}.html", t("informe", "report"), query.stem),
    )
}

/// One line per injected chain: where its host ended up. True if the search
/// put it far beyond chance.
fn grade(chain: &Truth, summary: &Summary) -> bool {
    let position = summary.ranking.iter().position(|r| r.host == chain.host);
    let (mark, style, place) = match position.map(|i| (i + 1, &summary.ranking[i])) {
        Some((rank, r)) if r.evalue <= ui::STRONG => ("✓", Style::Same, Some((rank, r.evalue))),
        Some((rank, r)) if r.evalue <= ui::WEAK => ("◐", Style::Warn, Some((rank, r.evalue))),
        Some((rank, r)) => ("✗", Style::Different, Some((rank, r.evalue))),
        None => ("✗", Style::Different, None),
    };
    let where_ = match place {
        Some((rank, evalue)) => tr!(
            "puesto {rank:<3} E = {}",
            "rank {rank:<3}  E = {}",
            i18n::evalue(evalue)
        ),
        None => t("sin parecido", "no resemblance").to_string(),
    };
    println!(
        "  {} {:<13} {:<14} {}",
        paint(mark, style),
        chain.label(),
        chain.host,
        paint(where_, style)
    );
    mark == "✓"
}

fn section(n: usize, title: &str) {
    let head = format!("━━ {n}/4 · {title} ");
    let fill = 78usize.saturating_sub(head.chars().count());
    println!(
        "\n{}\n",
        paint(format!("{head}{}", "━".repeat(fill)), Style::Brand)
    );
}
