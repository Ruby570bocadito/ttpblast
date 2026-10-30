# Contribuir a ttpblast

¡Gracias por pasarte! Lo que más ayuda ahora mismo, por orden:

1. **Datos reales** que pongan a prueba la calibración: aunque sea un resumen (cuántos hosts
   salen con E ≤ 1 en una red sin incidentes), con el JSON de `--json` basta. Nada de datos
   personales: el exportador de Sysmon ya deja fuera usuarios y líneas de comandos.
2. **Consultas** nuevas para [`queries/`](queries/), con su historia.
3. **Símbolos** para el alfabeto que cubran técnicas habituales en intrusiones.
4. Ideas para la [hoja de ruta](README.md#hoja-de-ruta), sobre todo para enmascarar la
   rutina de cada host y resistir el relleno.

*In English: issues and pull requests in English are just as welcome. The code comments are
in English; user-facing text is in Spanish and English.*

## Antes de enviar nada

Lo mismo que hace la CI en Windows, Linux y macOS:

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo run --release -- demo --details 1
```

La demo termina con su nota frente a la verdad («4 de 4 cadenas con E ≤ 0,01»): si baja,
algo ha cambiado en la detección y hay que explicarlo.

## Añadir un símbolo

1. Añádelo a [`alphabet/default.json`](alphabet/default.json) con `code` (tres letras),
   `technique` (un ID de ATT&CK que no esté ya), `tactic` (la principal), `name` en los dos
   idiomas y sus `rules`.
2. **El orden importa:** gana el primer símbolo que encaja. Lo más específico va primero
   (por eso `UEX`, un documento de Office que lanza un proceso, va antes que `PSH`).
3. Las reglas solo pueden mirar los campos que exporta
   [`scripts/export-sysmon.ps1`](scripts/export-sysmon.ps1): nombres de procesos, rutas y
   destinos de red. Nada de líneas de comandos.
4. Añade un test que codifique un evento de ejemplo (en `src/alphabet.rs` o
   `src/sysmon.rs`) y comprueba que el ruido sintético sigue sin codificarse
   (`cargo test noise_is_not_encoded`).
5. Si la telemetría sintética no tiene nada con ese símbolo, su puntuación de identidad será
   la máxima: piensa si hace falta algo de rutina para él en `src/synth.rs`.

## Añadir una consulta

- Un fichero `.txt` en `queries/` con una cabecera que cuente la historia y un comentario
  por paso, como [`queries/exfiltracion.txt`](queries/exfiltracion.txt).
- Patrones genéricos, de los que publican los informes de respuesta a incidentes: nada de
  indicadores concretos de una campaña.
- Pásala por la telemetría de la demo: si no hay ninguna cadena parecida inyectada, ningún
  host debería salir con E ≤ 1.

## Telemetría sintética

`ttpblast synth` es reproducible: la misma semilla da los mismos eventos, y las cifras del
README dependen de ello. La actividad nueva sale de **su propio flujo aleatorio** (mira
`routine_v2` en [`src/synth.rs`](src/synth.rs)), para que los eventos de versiones
anteriores no cambien. Hay un test que comprueba que el relleno no toca nada más.

## Puntuación y modelo nulo

Si cambias cómo se puntúa o cómo se baraja, vuelve a medir y actualiza las tablas del
README (en los dos idiomas):

```bash
python experiments/calibracion.py --seeds 20
python experiments/calibracion.py --seeds 20 --extra="--block 1" --work data/calibracion-b1
python experiments/evasion.py --seeds 20 --gaps 4/1,4/1:0/0
```

Cuenta también lo que no funcionó: el README tiene una sección para eso, y es de las más
útiles.

## Textos

- Todo lo que ve el usuario pasa por `tr!("español", "english")` o `i18n::t(…)`, con el
  español primero. Así es difícil cambiar uno y olvidar el otro.
- Errores que digan qué hacer: «falta --events» mejor que «argumento no válido».
- Los números, con `i18n::count`, `i18n::decimal` e `i18n::evalue`, que ponen bien los
  separadores en cada idioma.
- Colores con significado, no decorativos: `ui::Style` dice qué significa cada uno.

## Imágenes del README

```bash
cargo run --release -- demo > /dev/null
ttpblast search --query queries/phishing-lateral.txt --events data/demo/events.ndjson --details 2 --color always > salida.txt
python scripts/terminal-svg.py salida.txt docs/terminal.svg --title "ttpblast search"
```

(Para la imagen del README se recortan la tabla, el detalle de la variante y el veredicto.)

## Commits

Frases cortas en inglés y en imperativo, como el historial: «Add a Sysmon lab on a GitHub
Windows runner». Un cambio por commit cuando se pueda.

## Licencia

Cualquier contribución se licencia, como el proyecto, bajo MIT o Apache-2.0, a elección de
quien la use.
