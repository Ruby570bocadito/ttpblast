# Cambios

El formato sigue [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/) y las versiones,
[SemVer](https://semver.org/lang/es/). Mientras la versión empiece por 0, cualquier versión
menor puede romper algo; aquí se dice qué.

## [0.3.0] - sin publicar

Para usarla con registros de verdad y contra quien intenta esconderse: lee `.evtx` sin nada
más, entiende los registros propios de Windows cuando no hay Sysmon, pasa toda la
biblioteca de consultas de una vez, y con la máscara de rutina intercalar comandos
corrientes entre los pasos de una cadena ya no basta para esconderla. Sin `--mask`, las
búsquedas dan exactamente lo mismo que en la 0.2.0.

### Añadido

- **`--mask`** (en `search` y en `demo`): enmascara la rutina de cada host antes de alinear,
  como SEG y DUST en BLAST. Para cada consulta, es rutina lo que la consulta no usa y las
  técnicas de la consulta que el host repite (`--routine N`, 2 por defecto). La rutina se
  salta gratis pero se puede seguir emparejando; la que el alineamiento se salta dentro de
  la cadena sale también de los barajados; y un host cuyo mejor alineamiento no se salta
  nada se juzga como sin máscara. Con 1 a 4 comandos de relleno entre pasos, 60 de 80
  cadenas con E ≤ 0,01 (0 de 80 sin máscara); sin relleno, 66 (65). En la calibración, 17
  hosts benignos de 1.440 con E ≤ 1, frente a 12 (~36 si estuviera calibrado).
- La rutina saltada se ve en la salida: línea «Máscara» en la cabecera, `···` y cuántos
  eventos en el alineamiento, «rutina» en las pruebas, y en el informe HTML (vista general,
  alineamiento, cronología y pruebas). En JSON, `settings.mask`, `settings.routine`,
  `telemetry.masked_events`, `masked` en cada resultado y pasos con `"kind": "masked"`.
- `experiments/evasion.py --mask` mide cada coste con y sin máscara sobre la misma
  telemetría.
- La demo con `--padding` sugiere probar `--mask` cuando el relleno le esconde alguna
  cadena.
- README: qué se probó para la máscara y no funcionó (borrar la rutina, la rutina de cada
  host sola, dejarla fija en los barajados, puntuar con los costes normales, combinar dos
  búsquedas…), con sus cifras.
- **Ficheros `.evtx`**, leídos directamente y sin dependencias: cabeceras, bloques,
  registros y el XML binario con sus plantillas y sustituciones. Da lo mismo que
  `Get-WinEvent` en 8.240 registros reales de cuatro registros de Windows (Application,
  System y los dos de PowerShell). Un fichero dañado o manipulado no lo tumba: los registros
  ilegibles se saltan y se cuentan, sin un solo pánico en 400 ficheros alterados al azar. Un
  test que no corre por defecto compara el lector con Windows en cualquier `.evtx`.
- **Registros de Windows sin Sysmon**: procesos creados (Seguridad 4688), valores del
  registro escritos (4657), conexiones permitidas por el firewall (5156, solo salientes) y
  servicios instalados (Sistema 7045), en `.evtx`, por Winlogbeat o en exportaciones planas.
- **Carpetas como entrada**: `--events` lee todos los `.evtx`, `.ndjson`, `.jsonl` y
  `.json` de una carpeta, por ejemplo los recogidos de varios equipos en un incidente.
- **`ttpblast hunt`**: todas las consultas de la biblioteca (o de una carpeta) contra la
  misma telemetría, leída una sola vez; un veredicto por consulta, los hosts que señalan
  varias consultas en líneas aparte, `--json` para scripts y `--html CARPETA` con un informe
  por consulta.
- **5 consultas nuevas** (8 en total): `credenciales-rdp`, `psexec-destino`,
  `lolbins-persistencia`, `ntds-robo` y `acceso-remoto`. La biblioteca va dentro del
  binario.
- Laboratorio de Sysmon: comprueba también el registro de Sysmon leído como `.evtx` y el de
  Seguridad (con la auditoría de creación de procesos activada), pasa `hunt` por ellos y se
  ejecuta también en los PR que tocan la lectura de eventos.
- Las releases ponen como notas la sección de su versión en este CHANGELOG.

### Cambiado

- `encode --unmatched` nombra los eventos sin traducir por su proveedor e ID
  (`microsoft-windows-kernel-power 41`) en vez de «sin categoría».
- Los recuentos de lo ignorado hablan de eventos ilegibles o sin host, no de «líneas».
- Acciones de GitHub al día (checkout v7, upload-artifact v7, action-gh-release v3), que
  ya usan Node 24.

### Corregido

- La ayuda de `experiments/evasion.py` decía que los costes de `ttpblast` eran 4/1:1/0; son
  4/1.

## [0.2.0] - 2026-10-30

La versión que le da voz y cara: demo guiada, informe HTML, salida en inglés y colores, un
alfabeto más grande y corregido, y la primera medida de cuánto cuesta esconderle una cadena.

### Añadido

- **`ttpblast demo`**: esconde cuatro cadenas en telemetría sintética, las busca con dos
  consultas incluidas en el binario y se pone nota frente a la verdad. No necesita nada más
  que el ejecutable.
- **Informe HTML** (`--html FICHERO`): un solo fichero sin conexiones externas, con
  veredicto, vista general al estilo BLAST, la cadena frente a sus barajados (escala log,
  cola ajustada), cronología y pruebas. Modo claro y oscuro, legible en el móvil. Los datos
  de la telemetría van escapados y se escriben solo como texto.
- **Salida en inglés**: `--lang en`, `TTPBLAST_LANG=en` o el idioma del sistema. El
  español sigue siendo el idioma por defecto.
- **Personalidad en la terminal**: colores (solo en una terminal; `--color`, `NO_COLOR`),
  logo, veredicto final, barra de señal por resultado y, en cada detalle, dónde cae la
  cadena entre los barajados.
- **13 técnicas nuevas** en el alfabeto (31 en total), con nombre en español y en inglés:
  `WMI` (T1047), `PSX` (T1569.002, PsExec), `NTD` (T1003.003), `DEF` (T1562.001),
  `PRX` (T1218), `BIT` (T1197), `VSS` (T1490), `CLR` (T1070.001), `USR` (T1033),
  `PRC` (T1057), `NCD` (T1016), `NCX` (T1049) y `RMM` (T1219).
- **Consultas** `exfiltracion` y `ransomware-preludio`, con su historia en la cabecera.
- **Escenario de exfiltración** en la telemetría sintética, pensado para enseñar que cada
  host se compara consigo mismo (el servidor de copias hace lo mismo cada noche), y
  actividad rutinaria para los símbolos nuevos. Sale de un flujo aleatorio aparte: los
  31.870 eventos de la v0.1 siguen siendo los mismos, en el mismo orden.
- **Coste de evasión, medido**: `synth --padding N` intercala comandos corrientes entre los
  pasos de las cadenas y `experiments/evasion.py` mide qué queda. Resultado: un comando
  entre cada dos pasos basta para esconderlas (README, «Cuánto cuesta esconderse»).
- `--extra-open` y `--extra-extend`: los pasos de más pueden costar distinto que los que
  faltan.
- **Búsqueda en paralelo** (`--threads`, por defecto un hilo por núcleo), con el mismo
  resultado que con uno solo.
- **Más formatos de entrada**: Sysmon por Winlogbeat 6 y exportaciones planas con los campos
  de Sysmon en la raíz (`EventID`, `Hostname`…, como los Security Datasets de OTRF);
  `UtcTime` cuando no hay `@timestamp`.
- **JSON más rico**: `lang`, `summary` (el veredicto), los símbolos de la consulta con su
  técnica y táctica, el histograma de los barajados de cada resultado, táctica, nombre y
  puntuación en cada paso del alineamiento, y los costes de los huecos.
- Ayuda por orden (`ttpblast help search`, `ttpblast search --help`), opciones con la forma
  `--opcion=valor` y sugerencias para órdenes y opciones mal escritas («¿querías decir
  `search`?»).
- `scripts/terminal-svg.py`, para regenerar las imágenes de terminal del README.
- CI: la demo guiada de principio a fin y sus informes HTML como artefacto.

### Cambiado

- **`whoami`, `quser` y `qwinsta` son ahora `USR` (T1033, System Owner/User Discovery)**,
  como los clasifica ATT&CK; `ACD` (T1087, Account Discovery) pasa a ser `net.exe`. Las
  consultas que usaban `ACD` para `whoami` tienen que usar `USR`.
- `demo.sh` y `demo.cmd` ejecutan `ttpblast demo` (los argumentos van a la demo).
- La línea «Puntuación» solo enseña el rango de los símbolos de la consulta.
- `experiments/calibracion.py` lee la verdad de `truth.json`, mide las dos consultas de la
  demo y calcula lo esperado con los hosts realmente buscados. `truth.json` gana los campos
  `consulta` y `relleno`.
- Las rutas que se imprimen respetan el separador que escribió el usuario
  (`data/demo/events.ndjson` también en Windows).

### Corregido

- Los experimentos no encontraban el binario en Windows (faltaba el `.exe`).

## [0.1.0] - 2026-10-17

Primera versión: búsqueda de cadenas de ataque por alineamiento local (Smith-Waterman con
huecos afines), E-values por host a partir de barajados del propio host (cola exponencial o
Gumbel), línea base exacta al estilo EQL, telemetría sintética con tres cadenas inyectadas,
lectura de Sysmon (script de exportación y Winlogbeat 7), salida JSON, CI en Windows, Linux
y macOS, binarios en cada versión etiquetada y un laboratorio de Sysmon en GitHub Actions.

[0.3.0]: https://github.com/Ruby570bocadito/ttpblast/compare/v0.2.0...v0.3
[0.2.0]: https://github.com/Ruby570bocadito/ttpblast/compare/0e80116...v0.2.0
[0.1.0]: https://github.com/Ruby570bocadito/ttpblast/tree/0e80116
