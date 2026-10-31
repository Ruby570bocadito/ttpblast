# Guía de estilo de `ttpblast`

> Personalidad del proyecto: **rigor estadístico**.
> No vendemos certezas; cuantificamos la incertidumbre. Cada afirmación lleva,
> implícita o explícita, su margen de error.

Esta guía fija cómo habla y cómo se ve `ttpblast` en todas partes: README, mensajes
de la CLI, informes HTML, commits y documentación. Si dudas al redactar algo, vuelve aquí.

---

## 1. En una frase

**Statistical threat hunting para telemetría de endpoint.**

Buscamos variantes de una cadena de ataque conocida y, con un *E-value*, decimos si el
parecido es casualidad. Lo que nos distingue de un SIEM no es detectar más, sino **saber
cuándo callarnos**.

## 2. Historia de origen (el linaje, no el disfraz)

`ttpblast` hereda dos ideas de la bioinformática:

- **Alineamiento local** (Smith-Waterman): tolera sustituciones y huecos, igual que al
  comparar proteínas.
- **Estadística de Karlin-Altschul**: el *E-value* de BLAST, cuántos aciertos así
  esperarías por puro azar.

La analogía biológica (genoma, cepa, variante) se usa **para explicar** en la documentación,
nunca como estética ni como vocabulario de producto. En la interfaz hablamos de
hosts, cadenas de ataque y técnicas ATT&CK, no de ADN.

## 3. Voz y tono

- **Sobria y cuantitativa.** Da números, no adjetivos.
- **Honesta sobre sus límites.** Las limitaciones son una seña de seriedad, no letra
  pequeña que esconder. Un proyecto que promete de menos se gana la confianza del analista.
- **Respeta el tiempo del analista.** Prioriza: di qué merece atención y qué es ruido.
- **Sin alarmismo ni marketing.** Nada de "amenaza crítica detectada", "protección
  definitiva", "IA de última generación".

### Di esto / no digas esto

| Evita | Prefiere |
|---|---|
| "Amenaza detectada" | "3 hosts por encima del umbral de azar (E < 0,01)" |
| "Coincidencia encontrada" | "Alineamiento con E = 1,8 × 10⁻⁴" |
| "Protege tu red" | "Encuentra variantes de una cadena conocida" |
| "Alta probabilidad de ataque" | "Improbable por azar; requiere revisión humana" |
| "Falso positivo" (a secas) | "E = 2,59: lo esperable por azar en estos datos" |

Regla práctica: **si una frase no sobreviviría en un paper, reescríbela.**

## 4. Vocabulario

- **E-value**: siempre con guion, en cursiva la primera vez por sección si ayuda.
  Notación científica con coma decimal en español (`1,8 × 10⁻⁴`) y punto en inglés.
- **Cadena de ataque** (es) / *attack chain* (en): la secuencia de técnicas que buscas.
- **Variante**: una cadena que se alinea con la conocida pese a sustituciones o huecos.
- **Host / telemetría / técnica ATT&CK**: el lenguaje del dominio, no metáforas.
- Evita "cepa", "genoma", "mutación", "contagio" fuera de la sección de origen/analogía.

## 5. Números

- E-values: notación científica cuando `E < 0,01`; si no, dos decimales (`E = 2,59`).
- Nunca presentes un resultado sin su E-value o su umbral de referencia al lado.
- Al comparar con el azar, nómbralo explícitamente: *"el siguiente host tiene E = 2,59,
  que es lo esperable por azar."*

## 6. Paleta (ya en uso en el banner)

Base: tema oscuro de GitHub.

| Rol | Color | Uso |
|---|---|---|
| Fondo | `#0d1117` | Lienzo |
| Borde | `#30363d` | Marcos, separadores |
| Texto principal | `#e6edf3` | Titulares |
| Texto secundario | `#8b949e` | Subtítulos, anotaciones |
| Acento (marca) | `#2dd4bf` (teal) | "blast", lo que buscas |
| Señal fuerte | `#ff7b72` (rojo) | E-values muy improbables |
| Coincidencia | `#4ade80` (verde) | Pasos que alinean |
| Sustitución | `#fbbf24` (ámbar) | Pasos que divergen |

El color codifica **significado estadístico**, no decoración: rojo = improbable por azar,
verde = alineamiento, ámbar = divergencia. No introduzcas colores nuevos sin un significado.

## 7. Tipografía

- Datos, E-values, códigos de técnica y salida de CLI: **monoespaciada**
  (`Cascadia Mono`, `SF Mono`, `Menlo`, `Consolas`, `monospace`).
- Texto corrido: sans del sistema (`Segoe UI`, `-apple-system`, `Helvetica`, `Arial`).

## 8. Mensajes de la CLI

- Resultado = dato + referencia de azar. Ej.:
  `ws-finance-04  E = 1,8e-4   (variante: cmd, tarea programada, WinRM)`
- Los avisos reconocen la incertidumbre, no la ocultan:
  `aviso: matriz de puntuación inicial, sin calibrar en datos reales`
- Sin emojis en la salida estándar. Sin signos de exclamación.
