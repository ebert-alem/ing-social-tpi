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

# --- ESTILOS CSS CORPORATIVOS (SOC / THREAT INTELLIGENCE) ---
st.markdown(
    """
    <style>
        /* Tipografia y espaciado general */
        .block-container {
            padding-top: 2rem;
            padding-bottom: 3rem;
            max-width: 1380px;
        }
        
        /* Cabecera institucional */
        .soc-header {
            border-bottom: 2px solid rgba(148, 163, 184, 0.25);
            padding-bottom: 1.1rem;
            margin-bottom: 1.5rem;
        }
        .soc-kicker {
            font-size: 0.75rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.12em;
            color: #0284c7;
            margin-bottom: 0.25rem;
        }
        .soc-title {
            font-size: 1.75rem;
            font-weight: 800;
            letter-spacing: -0.02em;
            margin: 0 0 0.35rem 0;
            line-height: 1.2;
        }
        .soc-subtitle {
            font-size: 0.95rem;
            opacity: 0.78;
            margin: 0;
            font-weight: 400;
        }

        /* Estilizado de tarjetas de metricas nativas de Streamlit */
        div[data-testid="stMetric"] {
            background-color: rgba(148, 163, 184, 0.06);
            border: 1px solid rgba(148, 163, 184, 0.2);
            border-radius: 8px;
            padding: 14px 18px;
        }
        div[data-testid="stMetricLabel"] {
            font-size: 0.78rem !important;
            text-transform: uppercase;
            letter-spacing: 0.06em;
            font-weight: 600 !important;
            opacity: 0.8;
        }
        div[data-testid="stMetricValue"] {
            font-size: 1.65rem !important;
            font-weight: 700 !important;
        }

        /* Banner de infraestructura pasiva */
        .infra-panel {
            background-color: rgba(2, 132, 199, 0.07);
            border: 1px solid rgba(2, 132, 199, 0.25);
            border-left: 4px solid #0284c7;
            border-radius: 6px;
            padding: 12px 16px;
            margin: 12px 0;
            font-size: 0.9rem;
        }
        .infra-title {
            font-weight: 700;
            font-size: 0.78rem;
            text-transform: uppercase;
            letter-spacing: 0.06em;
            color: #0284c7;
            margin-bottom: 6px;
        }
        .tech-pill {
            display: inline-block;
            background-color: rgba(15, 23, 42, 0.08);
            border: 1px solid rgba(148, 163, 184, 0.35);
            border-radius: 4px;
            padding: 2px 9px;
            margin: 2px 6px 2px 0;
            font-family: 'Consolas', 'SFMono-Regular', monospace;
            font-size: 0.82rem;
            font-weight: 600;
        }

        /* Bloques internos de cada hallazgo */
        .finding-quote {
            border-left: 3px solid #64748b;
            background-color: rgba(148, 163, 184, 0.07);
            padding: 10px 14px;
            border-radius: 0 6px 6px 0;
            font-style: italic;
            margin-bottom: 12px;
            font-size: 0.93rem;
        }
        .finding-meta-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 10px;
            margin-bottom: 12px;
            font-size: 0.85rem;
        }
        .finding-meta-box {
            background-color: rgba(148, 163, 184, 0.05);
            border: 1px solid rgba(148, 163, 184, 0.18);
            border-radius: 6px;
            padding: 8px 12px;
        }
        .meta-label {
            font-size: 0.72rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            opacity: 0.65;
            display: block;
            margin-bottom: 2px;
        }
        .advisory-box {
            border-radius: 6px;
            padding: 10px 14px;
            margin-top: 8px;
            font-size: 0.88rem;
            line-height: 1.45;
        }
        .advisory-risk {
            background-color: rgba(217, 119, 6, 0.08);
            border: 1px solid rgba(217, 119, 6, 0.28);
            border-left: 4px solid #d97706;
        }
        .advisory-mitigation {
            background-color: rgba(2, 132, 199, 0.08);
            border: 1px solid rgba(2, 132, 199, 0.28);
            border-left: 4px solid #0284c7;
        }
        .advisory-title {
            font-weight: 700;
            font-size: 0.76rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 3px;
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
    <div class="soc-header">
        <div class="soc-kicker">Plataforma de Inteligencia de Amenazas &middot; Blue Team OSINT</div>
        <p class="soc-subtitle">
            Evaluación cuantitativa de la huella digital pública de una organización y su nivel de
            exposición ante vectores de pretexto (Spear Phishing, Vishing y Fraude Corporativo).
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
    col3.metric("Documentos Analizados", len(datos))
    col4.metric("Hallazgos Únicos", len(resultado.hallazgos))

    st.progress(int(resultado.pvi))
    st.caption(
        f"Puntaje bruto acumulado: {resultado.pvi_bruto} pts  |  "
        f"Modelo de saturación asintótica: PVI = 100 × (1 − e^(−bruto / {K_SATURACION}))  |  "
        f"Objetivo auditado: {empresa_input} ({dominio_input})"
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

    # --- DESGLOSE POR FUENTE Y CATEGORIA ---
    colA, colB = st.columns(2)
    with colA:
        st.subheader("Distribución de Riesgo por Fuente")
        if resultado.por_fuente:
            for fuente, valor in resultado.por_fuente.items():
                st.progress(min(100, int(valor * 5)), text=f"{fuente} — {valor} pts brutos")
        else:
            st.info("Sin hallazgos con riesgo atribuible.")

    with colB:
        st.subheader("Distribución por Dimensión Taxonómica")
        if resultado.por_categoria:
            for cat, valor in resultado.por_categoria.items():
                st.progress(min(100, int(valor * 10)), text=f"{cat} — {valor} pts ponderados")
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