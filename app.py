"""
Analizador de Exposicion OSINT e Indice de Vulnerabilidad a Pretextos (PVI).
Interfaz Streamlit con diseno ejecutivo orientado a Blue Team / Threat Intelligence.

La logica de analisis vive en pvi_core.py y la recoleccion en collectors.py,
ambos testeables de forma aislada.
"""

import html
import streamlit as st

from collectors import recolectar_datos_reales
from pvi_core import (
    K_SATURACION,
    PESOS_FUENTE,
    analizar_corpus,
)

# --- CONFIGURACION DE PAGINA ---
st.set_page_config(
    page_title="Auditor PVI | OSINT & Social Engineering Defense",
    page_icon="🛡️",
    layout="wide",
)

# --- ESTILOS CSS AESTHETIC (CYBER GLASSMORPHISM & MODERN DASHBOARD) ---
st.markdown(
    """
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;600&display=swap');

        html, body, [class*="css"] {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
        }
        .block-container {
            padding-top: 1.8rem;
            padding-bottom: 3rem;
            max-width: 1400px;
        }

        /* Hero Banner con gradiente sutil y glassmorphism */
        .hero-banner {
            background: linear-gradient(135deg, rgba(15, 23, 42, 0.92) 0%, rgba(30, 41, 59, 0.85) 50%, rgba(2, 132, 199, 0.18) 100%);
            border: 1px solid rgba(56, 189, 248, 0.25);
            border-radius: 16px;
            padding: 24px 28px;
            margin-bottom: 1.5rem;
            box-shadow: 0 10px 30px -10px rgba(2, 132, 199, 0.15);
            color: #f8fafc;
        }
        .soc-kicker {
            display: inline-block;
            background: rgba(56, 189, 248, 0.15);
            border: 1px solid rgba(56, 189, 248, 0.35);
            color: #38bdf8;
            font-size: 0.72rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.12em;
            padding: 4px 10px;
            border-radius: 999px;
            margin-bottom: 10px;
        }
        .soc-subtitle {
            font-size: 0.95rem;
            color: #cbd5e1;
            margin: 6px 0 0 0;
            font-weight: 400;
            line-height: 1.5;
        }

        /* Tarjetas de metricas con efecto Glass */
        div[data-testid="stMetric"] {
            background: linear-gradient(180deg, rgba(148, 163, 184, 0.08) 0%, rgba(148, 163, 184, 0.03) 100%);
            border: 1px solid rgba(148, 163, 184, 0.22);
            border-radius: 14px;
            padding: 16px 20px;
            box-shadow: 0 4px 20px -4px rgba(0, 0, 0, 0.08);
            transition: transform 0.2s ease, border-color 0.2s ease;
        }
        div[data-testid="stMetric"]:hover {
            transform: translateY(-2px);
            border-color: rgba(56, 189, 248, 0.45);
        }
        div[data-testid="stMetricLabel"] {
            font-size: 0.76rem !important;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            font-weight: 700 !important;
            opacity: 0.75;
        }
        div[data-testid="stMetricValue"] {
            font-size: 1.85rem !important;
            font-weight: 800 !important;
            letter-spacing: -0.02em;
        }

        /* Tarjeta del Velocimetro / Gauge PVI */
        .gauge-card {
            background: linear-gradient(145deg, rgba(15, 23, 42, 0.95), rgba(30, 41, 59, 0.9));
            border: 1px solid rgba(148, 163, 184, 0.22);
            border-radius: 16px;
            padding: 18px 22px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 20px;
            margin: 14px 0;
            color: #f8fafc;
            box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.2);
        }
        .gauge-info h4 {
            margin: 0 0 6px 0;
            font-size: 1.05rem;
            font-weight: 700;
            color: #f8fafc;
        }
        .gauge-info p {
            margin: 0;
            font-size: 0.85rem;
            color: #94a3b8;
            line-height: 1.45;
        }
        .status-badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 999px;
            font-size: 0.75rem;
            font-weight: 800;
            letter-spacing: 0.08em;
            text-transform: uppercase;
            margin-bottom: 8px;
        }

        /* Barras personalizadas con gradiente */
        .custom-bar-row {
            margin-bottom: 12px;
        }
        .custom-bar-header {
            display: flex;
            justify-content: space-between;
            font-size: 0.84rem;
            font-weight: 600;
            margin-bottom: 5px;
        }
        .custom-bar-track {
            width: 100%;
            height: 9px;
            background: rgba(148, 163, 184, 0.16);
            border-radius: 999px;
            overflow: hidden;
        }
        .custom-bar-fill {
            height: 100%;
            border-radius: 999px;
            background: linear-gradient(90deg, #0284c7 0%, #38bdf8 55%, #818cf8 100%);
        }
        .custom-bar-fill-cat {
            height: 100%;
            border-radius: 999px;
            background: linear-gradient(90deg, #6366f1 0%, #a855f7 60%, #ec4899 100%);
        }

        /* Banner de infraestructura pasiva */
        .infra-panel {
            background: linear-gradient(90deg, rgba(2, 132, 199, 0.12) 0%, rgba(99, 102, 241, 0.06) 100%);
            border: 1px solid rgba(56, 189, 248, 0.3);
            border-left: 4px solid #38bdf8;
            border-radius: 12px;
            padding: 14px 18px;
            margin: 14px 0;
            font-size: 0.9rem;
        }
        .infra-title {
            font-weight: 700;
            font-size: 0.76rem;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            color: #0284c7;
            margin-bottom: 8px;
        }
        .tech-pill {
            display: inline-block;
            background: rgba(2, 132, 199, 0.12);
            border: 1px solid rgba(56, 189, 248, 0.4);
            border-radius: 999px;
            padding: 3px 12px;
            margin: 3px 6px 3px 0;
            font-family: 'JetBrains Mono', 'Consolas', monospace;
            font-size: 0.8rem;
            font-weight: 600;
        }

        /* Bloques internos de cada hallazgo */
        .finding-quote {
            border-left: 4px solid #38bdf8;
            background: linear-gradient(90deg, rgba(56, 189, 248, 0.09) 0%, rgba(148, 163, 184, 0.03) 100%);
            padding: 12px 16px;
            border-radius: 0 10px 10px 0;
            font-style: italic;
            margin-bottom: 14px;
            font-size: 0.93rem;
            line-height: 1.5;
        }
        .finding-meta-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 10px;
            margin-bottom: 12px;
            font-size: 0.85rem;
        }
        .finding-meta-box {
            background-color: rgba(148, 163, 184, 0.06);
            border: 1px solid rgba(148, 163, 184, 0.2);
            border-radius: 10px;
            padding: 10px 14px;
        }
        .meta-label {
            font-size: 0.7rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.06em;
            opacity: 0.65;
            display: block;
            margin-bottom: 4px;
        }
        .advisory-box {
            border-radius: 10px;
            padding: 12px 16px;
            margin-top: 10px;
            font-size: 0.88rem;
            line-height: 1.5;
        }
        .advisory-risk {
            background: linear-gradient(90deg, rgba(245, 158, 11, 0.12) 0%, rgba(245, 158, 11, 0.04) 100%);
            border: 1px solid rgba(245, 158, 11, 0.3);
            border-left: 4px solid #f59e0b;
        }
        .advisory-mitigation {
            background: linear-gradient(90deg, rgba(16, 185, 129, 0.12) 0%, rgba(16, 185, 129, 0.04) 100%);
            border: 1px solid rgba(16, 185, 129, 0.3);
            border-left: 4px solid #10b981;
        }
        .advisory-title {
            font-weight: 700;
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.06em;
            margin-bottom: 4px;
        }
    </style>
    """,
    unsafe_allow_html=True,
)


def cargar_datos_simulacion(empresa: str) -> list[dict]:
    """Dataset controlado para demo y pruebas de regresion."""
    return [
        {
            "fuente": "Robots.txt / Sitemaps",
            "texto": (
                "Rutas publicadas en robots.txt del servidor: "
                "Disallow: /wp-admin/ | Disallow: /staging-portal/ | "
                "Disallow: /backup_config/ | Disallow: /intranet/"
            ),
            "url": "https://ejemplo.com/robots.txt",
        },
        {
            "fuente": "Noticias / Blog Corporativo",
            "texto": (
                f"Noticia: {empresa} comienzo la migracion de sus servidores a AWS "
                "junto a la consultora TechSolutions. El Gerente de Infraestructura "
                "Martin Gomez liderara el despliegue. El nuevo Director de Finanzas "
                "cabeza el proceso de licitacion de la obra publica."
            ),
            "url": "https://news.example/noticia-migracion",
        },
        {
            "fuente": "OSINT Redes / Dorking",
            "texto": (
                f"Busqueda activa en {empresa}: Analista de Soporte y Tesoreria con "
                "dominio de SAP y facturacion electronica. Enviar CV a Laura Perez "
                "del area de RRHH. Contacto: rrhh@ejemplo.com"
            ),
            "url": "https://www.linkedin.com/in/ejemplo-empleado",
        },
        {
            "fuente": "GitHub / Codigo",
            "texto": (
                f"Repositorio publico de {empresa}: Script de actualizacion del "
                "sistema interno conectado mediante token temporal para el proyecto "
                "de mantenimiento. Endpoint: https://api.ejemplo.com/v2/admin"
            ),
            "url": "https://github.com/ejemplo/script",
        },
        {
            "fuente": "Subdominios (Certificados)",
            "texto": (
                "Subdominios certificados del dominio: vpn.ejemplo.com, "
                "staging.ejemplo.com, admin.ejemplo.com, mail.ejemplo.com. "
                "Subdominios con nombre sensible: vpn.ejemplo.com (sospecha: vpn), "
                "staging.ejemplo.com (sospecha: staging), "
                "admin.ejemplo.com (sospecha: admin)"
            ),
            "url": "https://crt.sh/?q=ejemplo.com",
        },
        {
            "fuente": "Historico Web (Wayback)",
            "texto": (
                "Rutas historicas sensibles en el archivo web: "
                "https://ejemplo.com/admin/backup.sql | "
                "https://ejemplo.com/old/config.php | "
                "https://ejemplo.com/plantilla_nomina.xlsx"
            ),
            "url": "https://web.archive.org/cdx/search/cdx",
        },
        {
            "fuente": "DNS / Registros TXT",
            "texto": (
                "Registros DNS publicos del dominio: TXT: v=spf1 include:"
                "_spf.google.com ~all | Servidor de correo (MX): "
                "aspmx.l.google.com | Marcadores de verificacion/proveedor "
                "detectados: google-site-verification=abc123"
            ),
            "url": "https://dns.google/resolve?name=ejemplo.com",
        },
        {
            "fuente": "OSINT Redes / Dorking",
            "texto": (
                "Documento publico (planilla de nominas). Autor declarado en "
                "metadatos: Laura Perez. Texto del documento: Planilla de nominas "
                "2024, area de Tesoreria, acceso al servidor interno por VPN."
            ),
            "url": "https://ejemplo.com/docs/planilla.xlsx",
        },
        {
            "fuente": "Noticias / Blog Corporativo",
            "texto": (
                "Noticia sobre otra empresa no relacionada: Acme Corp realizo una "
                "migracion de servidores en otro pais sin mencion a la "
                "organizacion auditada."
            ),
            "url": "https://news.example/otra-empresa",
        },
    ]


# --- CABECERA EJECUTIVA ---
st.title("Auditor PVI — Análisis de Exposición OSINT e Ingeniería Social")
st.markdown(
    """
    <div class="hero-banner">
        <div class="soc-kicker">Threat Intelligence &middot; Defensive OSINT Engine</div>
        <p class="soc-subtitle">
            Recolección multi-fuente automatizada (10 conectores concurrentes), procesamiento de lenguaje natural
            híbrido (spaCy + EntityRuler) y cuantificación matemática del Índice de Vulnerabilidad a Pretextos (PVI).
        </p>
    </div>
    """,
    unsafe_allow_html=True,
)

# --- PANEL LATERAL DE CONFIGURACION ---
with st.sidebar:
    st.header("Parámetros de Auditoría")
    st.caption("Defina el objetivo organizacional y el alcance de recolección pasiva.")
    empresa_input = st.text_input("Organización Objetivo", value="Empresa Ejemplo S.A.")
    dominio_input = st.text_input("Dominio Primario", value="ejemplo.com")
    st.divider()
    modo = st.radio(
        "Modo de Operación (Módulo 1):",
        [
            "Simulación Controlada (Demo Segura)",
            "Recolección OSINT en Vivo (10 conectores)",
        ],
    )
    st.divider()
    ejecutar = st.button("Ejecutar Evaluación PVI", type="primary", width="stretch")

if not ejecutar:
    st.info(
        "Configure la organización objetivo en el panel lateral y presione "
        "**Ejecutar Evaluación PVI** para iniciar la correlación de fuentes abiertas."
    )

if ejecutar:
    with st.spinner("Ejecutando conectores OSINT y procesando lenguaje natural (spaCy)..."):
        if "Simulación" in modo:
            datos = cargar_datos_simulacion(empresa_input)
            estado = [
                {
                    "conector": "Simulación Controlada",
                    "estado": "ok",
                    "detalle": "Dataset determinista de validación",
                }
            ]
        else:
            datos, estado = recolectar_datos_reales(dominio_input, empresa_input)
            if not datos:
                st.error(
                    "No se obtuvieron resultados públicos o se detectó restricción de red. "
                    "Verifique el dominio o utilice el modo de Simulación Controlada."
                )
                st.stop()

        resultado = analizar_corpus(
            datos, empresa_input, dominio_input, estado_conectores=estado
        )

    # --- PANEL DE METRICAS EJECUTIVAS (KPIs) ---
    n_altos = sum(1 for h in resultado.hallazgos if h.severidad == "ALTO")
    n_medios = sum(1 for h in resultado.hallazgos if h.severidad == "MEDIO")
    n_bajos = sum(1 for h in resultado.hallazgos if h.severidad == "BAJO")

    col1, col2, col3, col4 = st.columns(4)
    col1.metric(
        "Índice PVI Global",
        f"{resultado.pvi} / 100",
        resultado.estado,
        delta_color="inverse" if resultado.pvi >= 35 else "normal",
    )
    col2.metric(
        "Nivel de Confianza",
        resultado.confianza,
        f"Cobertura {int(resultado.cobertura * 100)}%",
        delta_color="off",
    )
    col3.metric(
        "Documentos Analizados",
        len(datos),
        f"{len(resultado.descartes)} descartados por filtro",
        delta_color="off",
    )
    col4.metric(
        "Hallazgos Únicos",
        len(resultado.hallazgos),
        f"{n_altos} altos · {n_medios} medios · {n_bajos} bajos",
        delta_color="off",
    )

    # --- VELOCIMETRO / GAUGE SVG AESTHETIC PARA EL PVI ---
    color_pvi = (
        "#ef4444" if resultado.pvi >= 70
        else ("#f59e0b" if resultado.pvi >= 35 else "#10b981")
    )
    bg_badge = (
        "rgba(239, 68, 68, 0.18)" if resultado.pvi >= 70
        else ("rgba(245, 158, 11, 0.18)" if resultado.pvi >= 35 else "rgba(16, 185, 129, 0.18)")
    )
    circunferencia = 263.89  # 2 * pi * 42
    offset_svg = circunferencia * (1.0 - min(100.0, max(0.0, resultado.pvi)) / 100.0)

    st.markdown(
        f"""
        <div class="gauge-card">
            <div class="gauge-info">
                <span class="status-badge" style="background:{bg_badge}; color:{color_pvi}; border:1px solid {color_pvi};">
                    {html.escape(resultado.estado)}
                </span>
                <h4>Índice de Vulnerabilidad a Pretextos (PVI) — {html.escape(empresa_input)}</h4>
                <p>
                    Puntaje bruto acumulado: <strong>{resultado.pvi_bruto} pts</strong> &middot;
                    Curva exponencial: <code>PVI = 100 × (1 − e^(−bruto / {K_SATURACION}))</code> &middot;
                    Dominio: <code>{html.escape(dominio_input)}</code>
                </p>
            </div>
            <div style="flex-shrink:0;">
                <svg width="110" height="110" viewBox="0 0 100 100">
                    <circle cx="50" cy="50" r="42" fill="none" stroke="rgba(148,163,184,0.18)" stroke-width="9"/>
                    <circle cx="50" cy="50" r="42" fill="none" stroke="{color_pvi}" stroke-width="9"
                        stroke-dasharray="{circunferencia:.2f}" stroke-dashoffset="{offset_svg:.2f}"
                        stroke-linecap="round" transform="rotate(-90 50 50)"/>
                    <text x="50" y="54" text-anchor="middle" fill="#f8fafc" font-size="20" font-weight="800">
                        {resultado.pvi}
                    </text>
                    <text x="50" y="69" text-anchor="middle" fill="#94a3b8" font-size="8.5" font-weight="600">
                        DE 100
                    </text>
                </svg>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # --- BANNER DE INFRAESTRUCTURA VERIFICADA PASIVAMENTE ---
    if resultado.stack_verificado:
        pills_html = "".join(
            f'<span class="tech-pill">{html.escape(t)}</span>'
            for t in resultado.stack_verificado
        )
        st.markdown(
            f"""
            <div class="infra-panel">
                <div class="infra-title">Infraestructura y Servicios Confirmados Pasivamente (DNS / TLS / Robots)</div>
                <div>{pills_html}</div>
                <div style="margin-top: 6px; font-size: 0.82rem; opacity: 0.8;">
                    Activos verificados técnicamente y correlacionados con el perfil de exposición social de la organización.
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.divider()

    # --- DESGLOSE POR FUENTE Y CATEGORIA CON BARRAS GRADIENTE ---
    colA, colB = st.columns(2)
    with colA:
        st.subheader("Distribución de Riesgo por Fuente")
        if resultado.por_fuente:
            max_f = max(resultado.por_fuente.values()) or 1.0
            barras_fuente = []
            for fuente, valor in resultado.por_fuente.items():
                pct = min(100, max(6, int((valor / max(14.0, max_f)) * 100)))
                barras_fuente.append(
                    f'<div class="custom-bar-row">'
                    f'<div class="custom-bar-header"><span>{html.escape(fuente)}</span>'
                    f'<span>{valor} pts brutos</span></div>'
                    f'<div class="custom-bar-track"><div class="custom-bar-fill" style="width:{pct}%;"></div></div>'
                    f'</div>'
                )
            st.markdown("".join(barras_fuente), unsafe_allow_html=True)
        else:
            st.info("Sin hallazgos con riesgo atribuible.")

    with colB:
        st.subheader("Distribución por Dimensión Taxonómica")
        if resultado.por_categoria:
            max_c = max(resultado.por_categoria.values()) or 1.0
            barras_cat = []
            for cat, valor in resultado.por_categoria.items():
                pct = min(100, max(6, int((valor / max_c) * 100)))
                barras_cat.append(
                    f'<div class="custom-bar-row">'
                    f'<div class="custom-bar-header"><span>{html.escape(cat)}</span>'
                    f'<span>{valor} pts ponderados</span></div>'
                    f'<div class="custom-bar-track"><div class="custom-bar-fill-cat" style="width:{pct}%;"></div></div>'
                    f'</div>'
                )
            st.markdown("".join(barras_cat), unsafe_allow_html=True)
        else:
            st.info("Sin categorías detectadas.")

    st.divider()

    # --- REPORTE DETALLADO DE HALLAZGOS ---
    st.subheader(f"Matriz de Hallazgos y Vectores de Exposición ({len(resultado.hallazgos)})")

    if not resultado.hallazgos:
        st.success("No se detectaron vectores de exposición social relevantes tras el filtrado.")

    for idx, h in enumerate(resultado.hallazgos, start=1):
        etiqueta_sev = {
            "ALTO": "CRÍTICO / ALTO",
            "MEDIO": "MODERADO",
            "BAJO": "BAJO",
        }.get(h.severidad, h.severidad)

        titulo_expander = (
            f"#{idx:02d} [{etiqueta_sev}] {h.fuente}  |  "
            f"Impacto: +{h.impacto} pts (Riesgo intrínseco: {h.riesgo_intrinseco:.2f})  |  "
            f"Señales: {', '.join(h.terminos)}"
        )

        with st.expander(titulo_expander, expanded=(idx == 1)):
            oracion_segura = html.escape(h.oracion)
            st.markdown(
                f'<div class="finding-quote">"{oracion_segura}"</div>',
                unsafe_allow_html=True,
            )

            actores_txt = (
                html.escape(", ".join(h.actores))
                if h.actores
                else "No identificados explícitamente"
            )
            cats_txt = html.escape(", ".join(h.categorias))
            url_html = (
                f'<a href="{html.escape(h.url)}" target="_blank" rel="noopener noreferrer">{html.escape(h.url)}</a>'
                if h.url
                else "Fuente interna / Sin URL directa"
            )

            st.markdown(
                f"""
                <div class="finding-meta-grid">
                    <div class="finding-meta-box">
                        <span class="meta-label">Entidades / Actores (NER)</span>
                        <code>{actores_txt}</code>
                    </div>
                    <div class="finding-meta-box">
                        <span class="meta-label">Categorías Activadas</span>
                        <code>{cats_txt}</code>
                    </div>
                    <div class="finding-meta-box">
                        <span class="meta-label">Corroboración y Ponderación</span>
                        <span>{h.impacto} pts brutos ({h.confirmaciones} fuente(s))</span>
                    </div>
                    <div class="finding-meta-box">
                        <span class="meta-label">Evidencia de Origen</span>
                        <span>{url_html}</span>
                    </div>
                </div>
                <div class="advisory-box advisory-risk">
                    <div class="advisory-title">Análisis de Vector de Ingeniería Social</div>
                    <div>{html.escape(h.riesgo_desc)}</div>
                </div>
                <div class="advisory-box advisory-mitigation">
                    <div class="advisory-title">Contramedida Recomendada (Blue Team)</div>
                    <div>{html.escape(h.mitigacion)}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )

    st.divider()

    # --- SECCION DE AUDITORIA TECNICA Y METODOLOGIA (ORGANIZADA EN TABS) ---
    st.subheader("Trazabilidad Técnica y Gobernanza del Modelo")
    tab_superficie, tab_conectores, tab_descartes, tab_metodologia = st.tabs(
        [
            f"Superficie Técnica ({len(resultado.reconocimiento_tecnico)})",
            f"Estado de Conectores ({len(estado)})",
            f"Auditoría de Filtrado ({len(resultado.descartes)})",
            "Especificación Metodológica",
        ]
    )

    with tab_superficie:
        st.caption(
            "Activos de infraestructura recolectados (Subdominios TLS, Registros DNS, Directivas Robots.txt "
            "e Histórico Wayback). Se utilizan para verificar pasivamente el stack tecnológico y calcular "
            "el Anclaje de Credibilidad Técnica sin inflar artificialmente el conteo de hallazgos humanos."
        )
        if resultado.reconocimiento_tecnico:
            for rec in resultado.reconocimiento_tecnico:
                st.markdown(f"**{rec['fuente']}** — `{rec['url']}`")
                st.code(rec["detalle"], language="text")
        else:
            st.info("No se registraron activos de enumeración técnica en esta ejecución.")

    with tab_conectores:
        st.caption("Estado operativo de los conectores de recolección y cobertura alcanzada.")
        _etiquetas_estado = {
            "ok": "OPERATIVO (CON DATOS)",
            "vacio": "SIN RESULTADOS",
            "error": "FALLO DE CONEXIÓN",
        }
        st.dataframe(
            [
                {
                    "Conector OSINT": e["conector"],
                    "Estado Operativo": _etiquetas_estado.get(e["estado"], e["estado"].upper()),
                    "Detalle Técnico": e["detalle"],
                }
                for e in estado
            ],
            width="stretch",
            hide_index=True,
        )
        n_errores = sum(1 for e in estado if e["estado"] == "error")
        if n_errores:
            st.warning(
                f"Se registraron fallos en {n_errores} conector(es). El indicador de Confianza "
                "ajusta automáticamente su ponderación para reflejar esta menor cobertura."
            )

    with tab_descartes:
        st.caption(
            f"Registro auditable de {len(resultado.descartes)} fragmentos excluidos por las barreras "
            "de validación (ruido genérico, enumeración técnica sin contexto humano, código fuente, "
            "autores genéricos o falta de atribución al objetivo)."
        )
        if resultado.descartes:
            st.dataframe(resultado.descartes, width="stretch", hide_index=True)
        else:
            st.info("No se registraron descartes en esta ejecución.")

    with tab_metodologia:
        st.markdown(
            f"""
            **Fórmula de Saturación Exponencial:**  
            `PVI = 100 × (1 − e^(−PVI_bruto / K))` con constante de calibración **K = {K_SATURACION}**.

            - **Riesgo Intrínseco (`0.00 – 0.99`):** Calculado mediante combinación probabilística de las categorías detectadas más bonificaciones por actor identificado (`PER`/`ORG`), identificador directo, sinergia de la *Tríada de Pretexto* y factor de frescura temporal.
            - **Amortiguación por Fuente Repetida (`0.55^n`):** Impide que múltiples publicaciones de una misma fuente distorsionen el índice global, exigiendo exposición transversal en múltiples canales para alcanzar umbrales críticos.
            - **Anclaje de Credibilidad Técnica:** Incorpora de forma acotada la exposición de rutas internas y subdominios sensibles cuando coexisten con vectores humanos.
            """
        )
        st.dataframe(
            [
                {
                    "Fuente de Inteligencia": k,
                    "Peso Base (P_f)": v["peso"],
                    "Factor de Confianza (C_f)": v["confianza"],
                    "Dominio": v["categoria"],
                }
                for k, v in PESOS_FUENTE.items()
            ],
            width="stretch",
            hide_index=True,
        )