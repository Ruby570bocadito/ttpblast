//! The query library in `queries/`, built into the binary so that `demo`
//! and `hunt` need nothing but the executable.

pub struct Query {
    /// File name without `.txt`: how commands and reports name it.
    pub stem: &'static str,
    /// Where it lives in the repository, as the user would type it.
    pub path: &'static str,
    pub text: &'static str,
}

macro_rules! query {
    ($stem:literal) => {
        Query {
            stem: $stem,
            path: concat!("queries/", $stem, ".txt"),
            text: include_str!(concat!("../queries/", $stem, ".txt")),
        }
    };
}

pub const PHISHING: Query = query!("phishing-lateral");
pub const EXFILTRATION: Query = query!("exfiltracion");

/// Every query, in the order `hunt` reports them.
pub const LIBRARY: [Query; 8] = [
    PHISHING,
    EXFILTRATION,
    query!("ransomware-preludio"),
    query!("credenciales-rdp"),
    query!("psexec-destino"),
    query!("lolbins-persistencia"),
    query!("ntds-robo"),
    query!("acceso-remoto"),
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alphabet::Alphabet;
    use crate::search::parse_query;

    #[test]
    fn every_query_file_is_in_the_library_and_parses() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/queries");
        let mut files: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .filter_map(|e| e.ok()?.file_name().into_string().ok())
            .filter(|name| name.ends_with(".txt"))
            .collect();
        files.sort();
        let mut stems: Vec<String> = LIBRARY.iter().map(|q| format!("{}.txt", q.stem)).collect();
        stems.sort();
        assert_eq!(files, stems, "queries/ y la biblioteca deben coincidir");
        let alphabet = Alphabet::default_set();
        for query in &LIBRARY {
            let steps = parse_query(query.text, &alphabet).unwrap();
            assert!(
                steps.len() >= 4,
                "{}: una cadena de al menos 4 pasos",
                query.stem
            );
            assert!(
                query.text.starts_with('#'),
                "{}: empieza contando su historia",
                query.stem
            );
        }
    }
}
