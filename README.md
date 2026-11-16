<p align="center">
  <img src="assets/logo_auditor_pvi_svg_vectorial.svg" alt="Auditor PVI" width="680">
</p>

# Auditor PVI — Análisis de Exposición OSINT e Ingeniería Social

Herramienta de **OSINT pasivo con enfoque defensivo (Blue Team)** que evalúa qué tan fácil es construir un **pretexto de ingeniería social** contra una organización utilizando su propia información pública, resumiéndolo en un **Índice de Vulnerabilidad a Pretextos (PVI)** de 0 a 100.

> Proyecto académico para la materia **Ingeniería Social**. No es un producto comercial ni una herramienta ofensiva: su salida está estrictamente orientada a la concientización, auditoría y mitigación.

---

## ¿Qué problema resuelve?

Las herramientas OSINT tradicionales suelen devolver listas enormes de datos técnicos (IPs, subdominios, registros DNS), pero en ingeniería social la pregunta importante es otra: **¿qué tan útil es lo que la empresa publica todos los días para que un atacante invente una mentira creíble?**

Por ejemplo, si en una noticia la empresa cuenta que está migrando a *SAP* con una consultora externa, en un aviso de empleo pide conocimientos en *Fortinet* y en un PDF público quedó el nombre de usuario de alguien de *Tesorería*, un atacante ya tiene todas las piezas para llamar o mandar un correo haciéndose pasar por soporte de esa consultora.

**Auditor PVI** automatiza esa recolección en fuentes abiertas, separa el ruido irrelevante mediante Procesamiento de Lenguaje Natural (NLP) y traduce cada hallazgo en:
1. **Qué información quedó expuesta** y en qué fuente pública apareció.
2. **Qué vector de ingeniería social habilita** (a nivel de categoría defensiva, sin generar guiones de ataque).
3. **Qué contramedida concreta debe aplicar la organización** para cerrar esa brecha.

---

## Bases conceptuales y metodológicas

### 1. El "Kit del Pretexto" (5 dimensiones)

Un engaño creíble rara vez se arma con un dato suelto; necesita combinar varias piezas que se refuercen entre sí. Para medir el riesgo real de suplantación, el motor evalúa cuántas de las cinco dimensiones fundamentales de un pretexto quedan expuestas públicamente:

| Dimensión | Qué le aporta al atacante | Ejemplos detectados por el motor |
| :--- | :--- | :--- |
| **Identidad** | A quién suplantar o invocar | Proveedores, consultoras, soporte IT, RRHH, directivos (`PER` / `ORG`) |
| **Contexto** | La excusa o motivo verosímil | Migraciones, auditorías externas, licitaciones, despliegues, onboarding |
| **Canal** | A quién contactar y por qué vía | Correos corporativos, teléfonos, internos, autores en metadatos PDF/Office |
| **Jerga** | Credibilidad técnica e interna | Stack confirmado (SAP, AWS, Jira, Fortinet), rutas internas o credenciales |
| **Urgencia** | Palancas de presión psicológica | Cierres de trimestre, plazos críticos, vencimientos o secretos expuestos |

Además, cuando un mismo fragmento combina **Persona/Rol + Proceso Activo + Tecnología** (*Tríada de Pretexto*), el modelo aplica una bonificación de sinergia por su alto valor operativo para un atacante.

### 2. Separación entre Reconocimiento Técnico y Riesgo Social

Una ruta `/wp-admin/` en `robots.txt` o un subdominio `vpn.empresa.com` son datos de reconocimiento técnico, pero por sí solos no constituyen un relato social.

* **Exposición Social Directa:** Publicaciones, noticias, búsquedas laborales, código y documentos que revelan relaciones humanas, procesos o responsables generan hallazgos directos en la matriz PVI.
* **Anclaje de Credibilidad Técnica:** Los hallazgos de infraestructura pasiva (DNS, Certificados TLS, `robots.txt` y Wayback Machine) se verifican y se presentan en la pestaña de *Superficie Técnica*. Solo aportan un puntaje acotado de respaldo (*insider jargon*) cuando ya existen vectores sociales que un atacante pueda aprovechar.

### 3. Filtrado inteligente de ruido (NLP)

Para que el puntaje sea realista y no marque cualquier texto como peligroso, el motor utiliza **spaCy (`es_core_news_md`)** junto con un `EntityRuler` personalizado y barreras de limpieza que:
* **Descartan ruido genérico:** Ignoran avisos de cookies, menús de navegación, código fuente suelto, foros de terceros (StackOverflow, Reddit) y programas genéricos en los metadatos de documentos (*Microsoft Word*, *Adobe Acrobat*).
* **Unifican noticias repetidas:** Mediante un cálculo de **similitud temática** (descartando *stopwords* y comparando entidades clave), si una misma noticia o publicación aparece en varios portales distintos, se fusiona en un único hallazgo corroborado por múltiples fuentes en lugar de multiplicar artificialmente el puntaje.
* **Evitan coincidencias tautológicas:** Excluyen automáticamente el nombre de la propia organización auditada para que una empresa tecnológica (por ejemplo, *Salesforce*) no dispare alertas de software solo por nombrarse a sí misma.

### 4. Cálculo matemático del PVI y Confianza

Para evitar que organizaciones grandes saturen el índice en 100/100 por simple volumen de noticias, el motor utiliza un modelo de **saturación exponencial asintótica** en lugar de una suma lineal:

```text
PVI = 100 * (1 - e^(-PVI_bruto / K))    [con constante de calibración K = 26.0]
```

- **Gravedad de cada hallazgo individual (escala de `0.00` a `0.99`):**  
  El motor evalúa qué tan peligroso es cada fragmento detectado según el tipo de información que expone (por ejemplo, una ruta crítica o credencial vale `1.00`, un correo directo `0.80`, un proceso interno `0.65`, un cargo gerencial `0.60`, metadatos de autor `0.55` y menciones de software `0.45`).

  **Qué suma riesgo:** Si aparecen nombres de personas o empresas externas (`+0.25`), correos/URLs del dominio (`+0.20`), contexto técnico (`+0.10`), o si se detecta un secreto filtrado como una API key o webhook (salta directo a `0.99`).

  **Qué resta riesgo:** Si la publicación es antigua (del año `2022` o anterior), su impacto se reduce en un `20%` porque pierde vigencia operativa.

- **Control para evitar que una sola fuente infle el puntaje:**  
  Si una empresa tiene 20 noticias en Google News, no sería justo que eso dispare el índice global al máximo. Por eso, dentro de una misma fuente, el primer hallazgo aporta el `100%` de su valor, el segundo el `55%`, el tercero el `30%`, y así sucesivamente (`0.55^n`), con un límite máximo de `14.0 pts` por canal. De este modo, alcanzar un **Riesgo Alto (`>= 70`)** exige que existan filtraciones reales en varios canales distintos.

- **Cobertura y Nivel de Confianza (`ALTA`, `MEDIA`, `BAJA`):**  
  Indica qué tan fiable es la medición. Se calcula combinando en un `60%` cuántos conectores OSINT respondieron sin bloqueos ni errores de red (*Cobertura*) y en un `40%` la cantidad de hallazgos relevantes encontrados. Así, si el PVI da bajo, el analista puede distinguir si la organización realmente protege su información o si simplemente hubo restricciones de red durante la recolección.

### 5. Marco ético y legal (Ley 25.326)

* **OSINT pasivo puro:** Solo se consultan recursos públicos indexados sin enviar tráfico intrusivo ni interactuar con servidores privados.
* **Protección de Datos Personales (Ley 25.326, Argentina):** Incluye una opción de enmascaramiento que anonimiza nombres de personas (`J*** P***`) y correos (`m***@empresa.com`) tanto en pantalla como en los reportes exportados, evitando armar perfiles individuales.
* **Atestación auditable:** El escaneo en vivo exige confirmar explícitamente que se cuenta con autorización sobre el objetivo, dejando fecha y hora registradas en el reporte final.

---

## Arquitectura y Fuentes de Inteligencia

Cuando se ejecuta un análisis en vivo, la herramienta consulta **10 conectores en paralelo** sin necesidad de configurar claves de API pagas:

```text
               ┌── Robots.txt y Sitemaps recursivos      (Peso 7.0 | Conf. 0.95)
               ├── Metadatos y texto PDF / Office        (Peso 6.5 | Conf. 0.85)
               ├── Subdominios vía Certificados TLS      (Peso 6.5 | Conf. 0.90)
               ├── Histórico Web (Wayback Machine CDX)   (Peso 6.0 | Conf. 0.85)
10 Conectores  ├── Registros DNS-over-HTTPS (TXT/MX)     (Peso 6.0 | Conf. 0.85)
 Concurrentes  ├── GitHub API (Repositorios y Commits)   (Peso 6.0 | Conf. 0.85)
 (Pasivos)     ├── Dorking Dirigido (Perfiles y Docs)    (Peso 5.8 | Conf. 0.80)
               ├── Google News RSS Multivariante         (Peso 4.2 | Conf. 0.80)
               ├── Web Corporativa y security.txt        (Peso 3.5 | Conf. 0.90)
               └── Ingesta Manual (.txt, .pdf, .docx)    (Auditoría Híbrida/Local)
                                  │
                                  ▼
     Barreras de Filtrado  → Descarte de boilerplate, código fuente, foros de
                             terceros, autores genéricos (Adobe/Word) y duplicados
                                  │
                                  ▼
     Motor NLP Híbrido     → spaCy (es_core_news_md) + EntityRuler + Secret Scanning
                                  │
                                  ▼
     Scoring Exponencial   → Cálculo PVI + Kit 5 Piezas + Anclaje Técnico
                                  │
                                  ▼
     Dashboard y Reportes  → Interfaz Streamlit · Recálculo en vivo · HTML y PDF
```

| Archivo | Rol en el sistema |
| :--- | :--- |
| `app.py` | Interfaz ejecutiva en Streamlit, ingesta de archivos locales, depuración interactiva de hallazgos y exportación de reportes a HTML y PDF. |
| `collectors.py` | Orquestador multihilo (`ThreadPoolExecutor`) con los 10 conectores OSINT pasivos, reintentos con backoff y descarga en memoria de documentos públicos (`.pdf`, `.docx`, `.xlsx`). |
| `pvi_core.py` | Motor NLP (`spaCy` + `EntityRuler`), detección de secretos filtrados, filtros antiruido, deduplicación por similitud temática y cálculo matemático del PVI. |
| `tests/test_pvi.py` | Suite de pruebas unitarias y de regresión que valida normalización, relevancia, taxonomía, filtros de ruido, conectores y UI sin depender de la red. |

---

## Instalación

Requiere **Python 3.11 o superior**.

```bash
# 1. Crear y activar el entorno virtual
python -m venv .venv
# En Windows (PowerShell):
.venv\Scripts\Activate.ps1
# En Linux / macOS:
source .venv/bin/activate

# 2. Instalar dependencias (incluye el modelo es_core_news_md de spaCy)
pip install -r requirements.txt

# 3. (Opcional) Instalar reportlab para habilitar la descarga directa en PDF
pip install reportlab
```

---

## Uso de la aplicación

Para iniciar el dashboard interactivo, ejecutar desde la raíz del proyecto:

```bash
streamlit run app.py
```

El navegador se abrirá automáticamente en `http://localhost:8501`. Desde el panel lateral se puede elegir entre tres modos de operación:

1. **Simulación Controlada (Demo Segura):** Carga un caso de prueba determinista con datos ficticios. No necesita internet y es ideal para demostrar todas las funciones de la herramienta en el aula en pocos segundos.
2. **Recolección OSINT en Vivo (10 conectores):** Ejecuta la auditoría real en paralelo sobre el dominio y organización indicados (por ejemplo, `Globant` y `globant.com`). Requiere confirmar la casilla de autorización ética.
3. **Solo Evidencia Manual (Archivos Locales):** Permite arrastrar archivos `.txt` (formato `YYYY-MM-DD | fuente | texto` o líneas libres), `.pdf`, `.docx` o `.xlsx` desde la computadora. Es ideal para auditar un documento o comunicado de prensa *antes* de publicarlo en la web, o para realizar pruebas controladas sin depender de la red.

### Funciones interactivas del Dashboard
* **Depuración de hallazgos en tiempo real:** Permite desmarcar cualquier hallazgo puntual para excluirlo del análisis; el índice PVI, el velocímetro, la cobertura de las 5 piezas y los reportes se recalculan al instante.
* **Trazabilidad y auditoría del filtrado:** Incluye pestañas inferiores para inspeccionar la *Superficie Técnica*, el *Estado de Conectores*, la *Auditoría de Filtrado* (donde se listan todos los documentos descartados y el motivo exacto de su exclusión) y la *Especificación Metodológica y Legal*.
* **Exportación ejecutiva:** Descarga inmediata del informe completo en formato **HTML autocontenido** o **PDF**.

---

## Ejecución de pruebas automatizadas

El proyecto cuenta con una suite de pruebas unitarias para verificar el motor de análisis y los filtros de falsos positivos de forma aislada:

```bash
python -m unittest discover -s tests -v
```

---

## Descargo de responsabilidad

Software desarrollado con fines estrictamente académicos y educativos. Se entrega "tal cual", sin garantías de ningún tipo. El índice PVI es un indicador orientativo basado en fuentes públicas y no reemplaza una auditoría integral de seguridad. El análisis de dominios u organizaciones debe realizarse únicamente contando con autorización expresa del titular de los datos y en cumplimiento de la legislación vigente (incluyendo la Ley 25.326 de Protección de Datos Personales en Argentina).
