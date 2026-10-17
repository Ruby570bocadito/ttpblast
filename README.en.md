# ttpblast

[![CI](https://github.com/Ruby570bocadito/ttpblast/actions/workflows/ci.yml/badge.svg)](https://github.com/Ruby570bocadito/ttpblast/actions/workflows/ci.yml) · [Español](README.md)

> BLAST for endpoint telemetry: it searches your machines' events for **variants** of a
> known attack chain and tells you, with an E-value, whether the resemblance is chance.

**Status: research demo (v0.1).** It works end to end on synthetic telemetry. The scoring
matrix is a first version (not learned from data) and calibration on real data is still to
be shown: read [Limitations](#limitations) before trusting an E-value. The command-line
output is in Spanish for now.

```text
Resultados con E ≤ 10
   #  host              punt.   E-value  pasos    =    ~  huecos  duración
   1  ws-legal-02          44    1.7e-6    9/9    9    0       0    21 min
   2  ws-sales-03          18    4.0e-4    4/9    4    0       0     5 min
   3  ws-finance-04        29    1.4e-3    9/9    5    4       2    24 min
   4  ws-sales-04           8      2,59    2/9    2    0       0     5 min
   ...

Línea base    secuencia exacta, en orden, en ≤ 120 min (como `sequence … with maxspan` de EQL): 1 host
              ws-legal-02 (2026-10-07 10:02:00 → 10:23:00)

▸ ws-finance-04 · puntuación 29 · E = 1.4e-3 (p = 3.5e-5)
  2026-10-12 09:14:00 → 09:38:04 (24 min)

  consulta  UEX  PSH  C2W  ITT  RUN  ACD  ---  ---  SID  LSA  SMB
             |    +    |    |    +    |              +    |    +
  host      UEX  CMD  C2W  ITT  TSK  ACD  PSH  SID  RSD  LSA  WRM

  09:14:00  paso 1   UEX T1204.002  idéntico         winword.exe → cmd.exe
  09:16:36  paso 2   CMD T1059.003  similar a PSH    cmd.exe → cmd.exe
  ...
```

The exact search only finds the identical copy of the chain. `ttpblast` also finds the
variant (cmd instead of PowerShell, a scheduled task instead of a Run key, WinRM instead of
SMB, and two extra steps) and the chain that was cut short. All three stand well above
everything else: the next host has E ≈ 2.6, which is what chance gives.

## The problem

There are two usual ways to look for an attack chain in telemetry, and neither is good:

- **Exact query** (specific steps, in order). It stops matching as soon as the attacker
  swaps PowerShell for cmd, uses a scheduled task instead of a Run key, or adds one step.
- **Loose query** (some of the steps, in any order). False alarms show up, and there is no
  way to tell whether "5 of 9 steps" on this host is unusual or just normal for it.

Bioinformatics solved this same problem decades ago for DNA and proteins: **local
alignment** tolerates substitutions and gaps, and **Karlin-Altschul statistics** say how
many matches that good you would expect by chance (BLAST's E-value). `ttpblast` applies
both ideas to endpoint telemetry.

## Quick start

Linux, macOS or WSL:

```bash
git clone https://github.com/Ruby570bocadito/ttpblast && cd ttpblast
./demo.sh
```

Windows (cmd; in PowerShell, `.\demo.cmd`):

```bat
git clone https://github.com/Ruby570bocadito/ttpblast && cd ttpblast
demo
```

It needs Rust (2024 edition; tested with 1.97), installed from [rustup.rs](https://rustup.rs).
On Windows the installer also asks for Visual Studio's C++ build tools. The only dependency
is `serde_json`. Tagged versions also publish ready-made binaries in
[Releases](https://github.com/Ruby570bocadito/ttpblast/releases).

```bash
ttpblast synth --out data/demo                     # synthetic telemetry + ground truth (truth.json)
ttpblast search --query queries/phishing-lateral.txt --events data/demo/events.ndjson
ttpblast search ... --json                         # the same as JSON, for scripts and other tools
ttpblast encode --events data/demo/events.ndjson --host ws-finance-04   # a host's "genome"
ttpblast alphabet                                  # available symbols
ttpblast --help                                    # every option
```

## With your own telemetry (Windows + Sysmon)

[Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) is a free
Microsoft Sysinternals tool that logs what happens on a machine (processes, connections,
files, registry). The current version runs on Windows 11 or later and Windows Server 2019
or later.

In a PowerShell window opened **as administrator**, install it with the
[SwiftOnSecurity](https://github.com/SwiftOnSecurity/sysmon-config) configuration:

```powershell
$ProgressPreference = 'SilentlyContinue'
New-Item -ItemType Directory -Force C:\Tools\Sysmon | Out-Null
Invoke-WebRequest https://download.sysinternals.com/files/Sysmon.zip -OutFile C:\Tools\Sysmon\Sysmon.zip
Expand-Archive C:\Tools\Sysmon\Sysmon.zip -DestinationPath C:\Tools\Sysmon -Force
Invoke-WebRequest https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml -OutFile C:\Tools\Sysmon\sysmonconfig.xml
C:\Tools\Sysmon\Sysmon64.exe -accepteula -i C:\Tools\Sysmon\sysmonconfig.xml
```

Use the machine normally for a few days. Then, from the `ttpblast` folder (also as
administrator):

```powershell
cargo build --release
powershell -ExecutionPolicy Bypass -File .\scripts\export-sysmon.ps1 -Days 7
.\target\release\ttpblast.exe encode --events data\sysmon\events.ndjson --unmatched 15
.\target\release\ttpblast.exe search --query queries\phishing-lateral.txt --events data\sysmon\events.ndjson
```

- **Privacy.** [`scripts/export-sysmon.ps1`](scripts/export-sysmon.ps1) only exports paths
  of processes, files and registry keys, and network destinations. It does not export
  command lines, users or hashes. The output stays in `data\`, which git ignores. It also
  leaves out the events of its own runs (current and earlier ones), so as not to
  contaminate the measurement.
- **What to expect.** On a clean machine, no result should have a small E-value. If one
  does, it is a false alarm worth looking at: that is exactly what needs measuring.
- **A single machine.** With one host, `E = p`.
- **Process access.** The SwiftOnSecurity configuration does not log access to other
  processes (event 10), so the `LSA` step will never appear.
- **Connections.** Only outbound connections are translated.
- **Space.** Sysmon writes to the event log, which has a maximum size; when it fills up,
  the oldest events are lost.
- **Uninstall.** `C:\Tools\Sysmon\Sysmon64.exe -u`.

## How it works

1. **Alphabet.** Each relevant event becomes a symbol, a MITRE ATT&CK technique (`PSH` =
   T1059.001 PowerShell, `LSA` = T1003.001 LSASS access…). The rules live in
   [`alphabet/default.json`](alphabet/default.json), with Sigma-like syntax (`field`,
   `field|contains`, `field|endswith`). In the demo, 95 % of the events match no rule and
   are dropped.
2. **Sequences.** One per host, ordered in time and cut into stretches whenever more than an
   hour passes without activity (`--max-gap`), so a chain cannot borrow a step from the next
   day.
3. **Scoring.**
   - An identical step scores by how rare the symbol is in the data: `log2(1/q)`, rounded
     and clamped to 3–10, where `q` is its frequency. Matching an LSASS access weighs more
     than matching a PowerShell.
   - A substitution within the same tactic scores +2; across tactics, −3.
   - A gap costs −4, and −1 for each further step.
4. **Local alignment** of the query against each stretch: Smith-Waterman with affine gaps
   (Gotoh's variant), with a traceback to show which step matches which event.
5. **Significance.**
   - The host's own symbols are shuffled 200 times, keeping the length of the stretches,
     and the query is aligned against each shuffle.
   - Shuffling goes in blocks of 3 symbols (`--block`), to keep bursts of activity. The
     region of the best alignment, instead, is shuffled symbol by symbol, so the chain
     itself does not end up, in pieces, inside its own null model.
   - An exponential is fitted to the tail of those scores (the Karlin-Altschul form):
     `P(S ≥ s) ≈ P(S ≥ u) · e^(−λ(s−u))`, where `u` is the tail threshold (just above the
     median) and `λ` the decay rate.
   - `E = p × number of hosts` is how many hosts you would expect to see with a score like
     this by pure chance.
   - Each host is compared with itself. An administrator runs discovery all day, so their
     score of 10 is not surprising (E ≈ 21). A sales laptop's score of 18 is (E = 4.0·10⁻⁴).
   - The output shows the fit diagnostics: if the tail does not look exponential, it is
     flagged with ⚠.

## Results on synthetic data

The demo generates 40 Windows hosts over 14 days (~32,000 events): routine activity, three
administrators whose daily work resembles parts of an intrusion, a backup server that
compresses and uploads data every night, and three injected chains. `truth.json` keeps the
ground truth for evaluation.

| Scenario | What differs from the query | Exact search | ttpblast |
|---|---|---|---|
| `exacta` (exact) | nothing | yes | rank 1, E = 1.7·10⁻⁶ |
| `variante` (variant) | 4 techniques substituted and 2 extra steps | no | rank 3, E = 1.4·10⁻³ |
| `parcial` (partial) | only the first 4 steps | no | rank 2, E = 4.0·10⁻⁴ |

**Calibration** (`python3 experiments/calibracion.py --seeds 20`, and `--extra="--block 1"`
for the other rows): 20 datasets with different seeds, 37 benign hosts each. With
well-calibrated E-values, ~18.5 benign hosts would get E ≤ 1 and ~1.9 would get E ≤ 0.1.

| Shuffling | Null model | Benign E ≤ 1 | Benign E ≤ 0.1 | Exact (median E) | Variant | Partial |
|---|---|---|---|---|---|---|
| blocks of 3 (default) | `cola`, tail (default) | 9 | 0 | 4.8·10⁻⁶ | 4.6·10⁻⁴ | 4.5·10⁻² |
| blocks of 3 (default) | `gumbel` | 18 | 1 | 1.3·10⁻⁸ | 2.5·10⁻⁵ | 2.9·10⁻³ |
| blocks of 1 | `cola`, tail | 4 | 0 | 6.5·10⁻⁶ | 3.7·10⁻³ | 4.5·10⁻² |
| blocks of 1 | `gumbel` | 13 | 1 | 2.1·10⁻⁸ | 1.9·10⁻⁴ | 4.4·10⁻³ |

- In every row, the three chains are in the top 3 in all 20 datasets.
- **The exponential tail is conservative:** it gives fewer false alarms than it promises.
  With blocks of 3, the Gumbel is almost exactly calibrated.
  - The tail stays the default because it errs on the safe side and better describes the
    shape of the observed tail. The full Gumbel does not model the "floor" that appears when
    a rare symbol is in every shuffle.
  - This choice must be revisited with real telemetry.
- **What was tried and did not work:**
  - *Blocks of 3 without breaking up the aligned region.* The chain stays, in pieces, inside
    its own null model and gets penalised: the exact chain's median E rises to 4·10⁻² with
    the tail model.
  - *Leaving the aligned region out of the shuffles.* 135 benign hosts with E ≤ 1, out of
    ~18.5 expected. Taking away any host's best region leaves its null model without the
    very symbols its score is made of, and everything looks significant.
- **On real Windows.** The [`Sysmon lab`](.github/workflows/sysmon-lab.yml) workflow
  installs Sysmon on a throwaway GitHub Windows machine with this README's commands,
  generates benign activity (a build, `whoami`, `hostname`, `systeminfo`, `schtasks`, a
  download from PowerShell), exports with the script and analyses it.
  - First run: 46 events, 6 with a symbol (`PSH ACD SID SID TSK C2W`), exactly the commands
    that were run.
  - The best match with the chain had E = 0.54: no false alarm, even though those commands
    resemble an intrusion's discovery steps.
  - It checks the Sysmon pipeline end to end. It does not measure calibration: it is a few
    minutes of a build machine's activity.
- **This shows the mechanism works, not that it works on your network.** The data are
  generated by the project itself, with the same alphabet that then searches them, and
  synthetic benign activity is more random than real activity.

## Honest comparison

| | ttpblast | Exact sequence query (e.g. EQL `sequence`) |
|---|---|---|
| Variants (substituted technique, extra or missing step) | yes | no |
| Is this resemblance unusual on this host? | per-host E-value | not answered |
| Cost | alignment + 200 shuffles per host (0.2 s in the demo) | very low |
| Maturity | research demo | mature production tools |
| Explanation | step-by-step alignment with its events | matching events |

It does not replace exact rules: it is for hunting variants of known chains and for
prioritising.

## Limitations

- **Only tested on synthetic data.** The number one open question is whether E-values stay
  calibrated on real telemetry.
- **The scoring matrix is hand-made:** symbol rarity plus a rule by tactic. The idea is to
  learn it from real chains, the way BLOSUM was learned from protein blocks.
- **Shuffling destroys part of the temporal structure.** Blocks of 3 keep short bursts. If
  real activity has longer structure, the null model will be too random and E-values will
  come out optimistic. This needs measuring on real data. Using similar hosts as a
  reference is on the roadmap.
- **Stretches use a fixed time gap.** A slow chain, with hours between steps, gets cut
  (`--max-gap` adjusts it). The alignment does not use timing inside a stretch either.
- **One host at a time.** It does not follow lateral movement from one host to another.
- **The alignment is the optimum for the score,** not always the one a person would pick.
  In the variant above it pairs SID with RSD and leaves the real SID as an extra step,
  because affine gaps prefer one long gap to two short ones.
- **Scale.** The cost is O(m·n) per stretch, plus the shuffles. Millions of events will
  need a seed index, as BLAST has.
- **Input format.** NDJSON with ECS-style fields (`host.name`, `@timestamp`, `process.name`,
  `process.parent.name`, `destination.port`, `file.path`, `registry.path`). Process access
  uses `process.target.name`, which is not standard. Sysmon events (exported with the script
  or shipped by Winlogbeat) are translated automatically. Other sources need field mapping
  or an adapter.
- **Adaptive adversary.** Someone who knows the method can pad the chain with benign steps
  or spread it out in time. How much that costs them needs measuring.

## Roadmap

1. Test the alphabet on public datasets of simulated attacks: do two runs of the same
   scenario align better than with the noise?
2. Learn the substitution matrix from real chains.
3. Calibration on real telemetry, and choosing the null model: tail or Gumbel, block size,
   similar hosts as a reference.
4. More input sources: EVTX files directly and NDJSON output of open-source EDRs.
5. A seed (k-mer) index for large volumes.
6. Time-dependent gaps, and chains across hosts.
7. Measure the cost of evasion: how many padding steps, or how much time, it takes to hide
   a chain.

## Formats

- **Events:** one JSON object per line. Nested objects and dotted keys are equivalent, and
  values are compared case-insensitively.
- **Queries:** symbol codes or technique IDs, separated by spaces, commas or arrows; `#`
  starts a comment. See [`queries/phishing-lateral.txt`](queries/phishing-lateral.txt).
- **Alphabet:** JSON with `symbols`. Each symbol has `code`, `technique`, `tactic`, `name`
  and a list of `rules`. The first symbol that matches wins. Load another one with
  `--alphabet`.

## Responsible use

This is a defensive tool: it searches your own telemetry. The demo's synthetic data are
made-up events with example domains (`*.example.*`) and private addresses. They contain no
code or malware samples.

## License

At your option, [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), as is usual in Rust.
Unless you explicitly state otherwise, any contribution you submit for inclusion in the
project is dual-licensed in the same way, without any additional terms or conditions.
