# ttpblast

> BLAST para la telemetría de endpoint: busca **variantes** de una cadena de ataque conocida
> en los eventos de tus máquinas y te dice, con un E-value, si el parecido es casualidad.

**Estado: demo de investigación (v0.1).** Funciona de principio a fin sobre telemetría
sintética. La matriz de puntuación es inicial (no aprendida de datos) y la calibración en
datos reales está por demostrar: lee [Limitaciones](#limitaciones) antes de fiarte de un
E-value.

```text
Resultados con E ≤ 10
   #  host              punt.   E-value  pasos    =    ~  huecos  duración
   1  ws-legal-02          44    6.8e-6    9/9    9    0       0    21 min
   2  ws-sales-03          18    1.7e-3    4/9    4    0       0     5 min
   3  ws-finance-04        29    4.2e-3    9/9    5    4       2    24 min
   4  ws-sales-04           8      1,99    2/9    2    0       0     5 min
   ...

Línea base    secuencia exacta, en orden, en ≤ 120 min (como `sequence … with maxspan` de EQL): 1 host
              ws-legal-02 (2026-10-07 10:02:00 → 10:23:00)

▸ ws-finance-04 · puntuación 29 · E = 4.2e-3 (p = 1.0e-4)
  2026-10-12 09:14:00 → 09:38:04 (24 min)

  consulta  UEX  PSH  C2W  ITT  RUN  ACD  ---  ---  SID  LSA  SMB
             |    +    |    |    +    |              +    |    +
  host      UEX  CMD  C2W  ITT  TSK  ACD  PSH  SID  RSD  LSA  WRM

  09:14:00  paso 1   UEX T1204.002  idéntico         winword.exe → cmd.exe
  09:16:36  paso 2   CMD T1059.003  similar a PSH    cmd.exe → cmd.exe
  09:20:23  paso 3   C2W T1071.001  idéntico         rundll32.exe → cdn-sync.example.net:443
  09:22:18  paso 4   ITT T1105      idéntico         certutil.exe crea c:\users\public\svc.exe
  09:24:51  paso 5   TSK T1053.005  similar a RUN    cmd.exe → schtasks.exe
  ...
```

La búsqueda exacta solo encuentra la copia idéntica de la cadena. `ttpblast` encuentra
también la variante (con cmd en vez de PowerShell, tarea programada en vez de clave Run,
WinRM en vez de SMB y dos pasos de más) y la cadena cortada a medias. Las tres quedan muy
por encima de todo lo demás: el siguiente host tiene E ≈ 2, que es lo esperable por azar.

## El problema

Para buscar una cadena de ataque en la telemetría hay dos opciones habituales, y ninguna
es buena:

- **Consulta exacta** (pasos concretos, en orden). Basta con que el atacante cambie
  PowerShell por cmd, use una tarea programada en lugar de la clave Run o meta un paso de
  más para que la consulta ya no coincida.
- **Consulta relajada** (algunos pasos, en cualquier orden). Aparecen falsas alarmas, y no
  hay forma de saber si "5 de 9 pasos" en este host es raro o es lo normal.

La bioinformática resolvió ese mismo problema hace décadas para el ADN y las proteínas: el
**alineamiento local** tolera sustituciones y huecos, y la **estadística de Karlin-Altschul**
dice cuántos aciertos así esperarías por azar (el E-value de BLAST). `ttpblast` aplica las
dos ideas a la telemetría de endpoint.

## Inicio rápido

Linux, macOS o WSL:

```bash
git clone https://github.com/Ruby570bocadito/ttpblast && cd ttpblast
./demo.sh
```

Windows (cmd; en PowerShell, `.\demo.cmd`):

```bat
git clone https://github.com/Ruby570bocadito/ttpblast && cd ttpblast
demo
```

Necesita Rust (edición 2024; probado con 1.97), que se instala desde
[rustup.rs](https://rustup.rs). En Windows, el instalador pide además las herramientas de
compilación de C++ de Visual Studio. La única dependencia es `serde_json`.

```bash
ttpblast synth --out data/demo                     # telemetría sintética + verdad (truth.json)
ttpblast search --query queries/phishing-lateral.txt --events data/demo/events.ndjson
ttpblast encode --events data/demo/events.ndjson --host ws-finance-04   # el "genoma" de un host
ttpblast alphabet                                  # símbolos disponibles
ttpblast --help                                    # todas las opciones
```

## Con tu propia telemetría (Windows + Sysmon)

[Sysmon](https://learn.microsoft.com/es-es/sysinternals/downloads/sysmon) es una
herramienta gratuita de Microsoft Sysinternals que registra lo que pasa en el equipo
(procesos, conexiones, ficheros, registro). La versión actual funciona en Windows 11 o
posterior y en Windows Server 2019 o posterior.

En una PowerShell abierta **como administrador**, instálalo con la configuración de
[SwiftOnSecurity](https://github.com/SwiftOnSecurity/sysmon-config):

```powershell
$ProgressPreference = 'SilentlyContinue'
New-Item -ItemType Directory -Force C:\Tools\Sysmon | Out-Null
Invoke-WebRequest https://download.sysinternals.com/files/Sysmon.zip -OutFile C:\Tools\Sysmon\Sysmon.zip
Expand-Archive C:\Tools\Sysmon\Sysmon.zip -DestinationPath C:\Tools\Sysmon -Force
Invoke-WebRequest https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml -OutFile C:\Tools\Sysmon\sysmonconfig.xml
C:\Tools\Sysmon\Sysmon64.exe -accepteula -i C:\Tools\Sysmon\sysmonconfig.xml
```

Usa el equipo con normalidad unos días. Después, desde la carpeta de `ttpblast` (y también
como administrador):

```powershell
cargo build --release
powershell -ExecutionPolicy Bypass -File .\scripts\export-sysmon.ps1 -Days 7
.\target\release\ttpblast.exe encode --events data\sysmon\events.ndjson
.\target\release\ttpblast.exe search --query queries\phishing-lateral.txt --events data\sysmon\events.ndjson
```

- **Privacidad.** [`scripts/export-sysmon.ps1`](scripts/export-sysmon.ps1) solo exporta
  rutas de procesos, ficheros y claves de registro, y destinos de red. No exporta líneas
  de comandos, usuarios ni hashes. El resultado queda en `data\`, que git ignora.
- **Qué esperar.** En un equipo limpio, lo normal es que ningún resultado tenga un E-value
  pequeño. Si alguno lo tiene, es una falsa alarma que merece la pena mirar: es justo lo que
  hay que medir.
- **Un solo equipo.** Con un único host, `E = p`.
- **Accesos a procesos.** La configuración de SwiftOnSecurity no registra accesos a otros
  procesos (evento 10), así que el paso `LSA` nunca aparecerá.
- **Conexiones.** Solo se traducen las conexiones salientes.
- **Espacio.** Sysmon escribe en el registro de eventos, que tiene un tamaño máximo; si se
  llena, se pierden los eventos más antiguos.
- **Desinstalar.** `C:\Tools\Sysmon\Sysmon64.exe -u`.

## Cómo funciona

1. **Alfabeto.** Cada evento relevante se convierte en un símbolo, una técnica de MITRE
   ATT&CK (`PSH` = T1059.001 PowerShell, `LSA` = T1003.001 acceso a LSASS…). Las reglas
   están en [`alphabet/default.json`](alphabet/default.json), con sintaxis al estilo Sigma
   (`campo`, `campo|contains`, `campo|endswith`). En la demo, el 95 % de los eventos no
   encaja con ninguna regla y se descarta.
2. **Secuencias.** Una por host, ordenada en el tiempo y cortada en tramos cuando pasa más
   de una hora sin actividad (`--max-gap`), para que una cadena no tome prestado un paso
   del día siguiente.
3. **Puntuación.**
   - Un paso idéntico puntúa según lo raro que es el símbolo en los datos: `log2(1/q)`,
     redondeado y acotado a 3–10, donde `q` es su frecuencia. Acertar un acceso a LSASS
     pesa más que acertar un PowerShell.
   - Una sustitución dentro de la misma táctica puntúa +2; entre tácticas distintas, −3.
   - Un hueco cuesta −4, y −1 por cada paso más.
4. **Alineamiento local** de la consulta contra cada tramo: Smith-Waterman con huecos
   afines (variante de Gotoh), con *traceback* para enseñar qué paso corresponde a qué
   evento.
5. **Significación.**
   - Se barajan 200 veces los símbolos del propio host, manteniendo la longitud de los
     tramos, y se alinea la consulta contra cada barajado.
   - A la cola de esas puntuaciones se le ajusta una exponencial (la forma de
     Karlin-Altschul): `P(S ≥ s) ≈ P(S ≥ u) · e^(−λ(s−u))`, donde `u` es el umbral de la
     cola (justo por encima de la mediana) y `λ` la tasa de caída.
   - `E = p × número de hosts` es el número de hosts que esperarías ver con una
     puntuación así por puro azar.
   - Cada host se compara consigo mismo. Un administrador hace descubrimiento todo el día,
     así que su puntuación de 10 no sorprende (E = 5,4). La puntuación de 18 de un
     portátil de ventas sí sorprende (E = 1,7·10⁻³).
   - La salida enseña el diagnóstico del ajuste: si la cola no parece exponencial, lo
     marca con ⚠.

## Resultados en datos sintéticos

La demo genera 40 hosts Windows durante 14 días (~32.000 eventos). Incluye actividad
rutinaria, tres administradores cuyo trabajo diario se parece a trozos de una intrusión, un
servidor de copias que comprime y sube datos cada noche, y tres cadenas inyectadas.
`truth.json` guarda la verdad para evaluar.

| Escenario | Qué cambia respecto a la consulta | Búsqueda exacta | ttpblast |
|---|---|---|---|
| `exacta` | nada | sí | puesto 1, E = 6,8·10⁻⁶ |
| `variante` | 4 técnicas sustituidas y 2 pasos de más | no | puesto 3, E = 4,2·10⁻³ |
| `parcial` | solo los 4 primeros pasos | no | puesto 2, E = 1,7·10⁻³ |

**Calibración** (`python3 experiments/calibracion.py --seeds 20`): 20 conjuntos de datos
con semillas distintas, 37 hosts benignos en cada uno. Si los E-values estuvieran bien
calibrados, saldrían ~18,5 hosts benignos con E ≤ 1 y ~1,9 con E ≤ 0,1.

| Modelo nulo | Benignos con E ≤ 1 | Benignos con E ≤ 0,1 | Exacta (E mediana) | Variante (E mediana) | Parcial (E mediana) |
|---|---|---|---|---|---|
| `cola` (por defecto) | 4 | 0 | 6,5·10⁻⁶ | 3,7·10⁻³ | 5,0·10⁻² |
| `gumbel` | 13 | 1 | 2,1·10⁻⁸ | 1,9·10⁻⁴ | 4,4·10⁻³ |

- Con los dos modelos, las tres cadenas quedan entre los 3 primeros puestos en los 20
  conjuntos.
- **Los dos modelos son conservadores** en estos datos: dan menos falsas alarmas de las
  que prometen. La cola exponencial lo es más.
  - Es la opción por defecto porque se equivoca hacia el lado seguro y su forma describe
    mejor la cola que se observa.
  - La Gumbel completa no modela el "suelo" que se forma cuando un símbolo raro aparece en
    todos los barajados.
- **Esto demuestra que el mecanismo funciona, no que funcione en tu red.** Los datos los
  genera el propio proyecto, con el mismo alfabeto que luego los busca, y la actividad
  benigna sintética es más aleatoria que la real.

## Comparación honesta

| | ttpblast | Consulta de secuencia exacta (p. ej. `sequence` de EQL) |
|---|---|---|
| Variantes (técnica sustituida, paso extra o que falta) | sí | no |
| ¿Es raro este parecido en este host? | E-value por host | no lo dice |
| Coste | alineamiento + 200 barajados por host (0,3 s en la demo) | muy bajo |
| Madurez | demo de investigación | herramientas maduras en producción |
| Explicación | alineamiento paso a paso con sus eventos | eventos que coinciden |

No sustituye a las reglas exactas: sirve para cazar (*hunting*) variantes de cadenas
conocidas y para priorizar.

## Limitaciones

- **Solo se ha probado con datos sintéticos.** La pregunta abierta número uno es si los
  E-values siguen calibrados con telemetría real.
- **La matriz de puntuación es a mano:** rareza del símbolo más una regla por tácticas. La
  idea de fondo es aprenderla de cadenas reales, como se aprendió BLOSUM de bloques de
  proteínas.
- **Barajar destruye la estructura temporal** (la actividad real llega en ráfagas).
  - `--block N` baraja por bloques y conserva algo de esa estructura.
  - Pero también conserva trozos de la propia cadena dentro del modelo nulo, que entonces
    la penaliza. En la demo, `--block 3` sube el E de la cadena exacta de 7·10⁻⁶ a 0,07.
  - Un modelo nulo que excluya la región alineada, o que tome como referencia hosts
    parecidos, está en la hoja de ruta.
- **Los tramos usan un hueco de tiempo fijo.** Una cadena lenta, con horas entre pasos, se
  corta (`--max-gap` lo ajusta). Además, el alineamiento no usa los tiempos dentro de un
  tramo.
- **Un host cada vez.** No sigue el movimiento lateral de un host a otro.
- **El alineamiento es el óptimo según la puntuación,** no siempre el que elegiría una
  persona. En la variante de arriba empareja SID con RSD y deja el SID real como paso
  extra, porque los huecos afines prefieren un hueco largo a dos cortos.
- **Escala.** El coste es O(m·n) por tramo, más los barajados. Para millones de eventos
  hará falta un índice de semillas, como hace BLAST.
- **Formato de entrada.** NDJSON con campos al estilo ECS (`host.name`, `@timestamp`,
  `process.name`, `process.parent.name`, `destination.port`, `file.path`,
  `registry.path`). El acceso a procesos usa `process.target.name`, que no es estándar.
  Los eventos de Sysmon (exportados con el script o enviados por Winlogbeat) se traducen
  solos. Otras fuentes necesitan mapear campos o un adaptador.
- **Adversario adaptativo.** Quien conozca el método puede rellenar la cadena con pasos
  benignos o espaciarla en el tiempo. Hay que medir cuánto le cuesta.

## Hoja de ruta

1. Probar el alfabeto con datos públicos de ataques simulados (p. ej. Security Datasets de
   OTRF): ¿se alinean dos ejecuciones del mismo escenario mejor que con el ruido?
2. Aprender la matriz de sustitución de cadenas reales.
3. Calibración con telemetría real, y decidir el modelo nulo: cola o Gumbel; barajado
   excluyendo la región alineada; hosts parecidos como referencia.
4. Más fuentes de entrada: ficheros EVTX directamente y salidas NDJSON de EDR abiertos.
5. Índice de semillas (k-mers) para volúmenes grandes.
6. Huecos que dependan del tiempo, y cadenas entre hosts.
7. Medir el coste de evasión: cuántos pasos de relleno o cuánto tiempo hacen falta para
   esconder una cadena.

## Formatos

- **Eventos:** un JSON por línea. Los objetos anidados y las claves con puntos son
  equivalentes, y los valores se comparan sin distinguir mayúsculas.
- **Consultas:** códigos de símbolo o IDs de técnica, separados por espacios, comas o
  flechas; `#` inicia un comentario. Ver [`queries/phishing-lateral.txt`](queries/phishing-lateral.txt).
- **Alfabeto:** JSON con `symbols`. Cada símbolo tiene `code`, `technique`, `tactic`,
  `name` y una lista `rules`. Gana el primer símbolo que encaja. Se carga otro con
  `--alphabet`.

## Uso responsable

Es una herramienta defensiva: busca en tu propia telemetría. Los datos sintéticos de la
demo son eventos inventados con dominios de ejemplo (`*.example.*`) y direcciones privadas.
No contienen código ni muestras de malware.

## Licencia

A tu elección, [MIT](LICENSE-MIT) o [Apache-2.0](LICENSE-APACHE), como es habitual en Rust.
Salvo que digas lo contrario, cualquier contribución que envíes para incluirla en el
proyecto se licencia de esa misma doble forma, sin condiciones adicionales.
