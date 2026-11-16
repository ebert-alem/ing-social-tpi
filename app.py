"""
Auditor PVI | Analizador de Exposicion OSINT e Indice de Vulnerabilidad a Pretextos.
Interfaz Streamlit con diseno ejecutivo orientado a Blue Team / Threat Intelligence.
"""

from datetime import datetime
import html
import io
import re
import xml.etree.ElementTree as ET
import zipfile

import streamlit as st
from pypdf import PdfReader

from collectors import recolectar_datos_reales
from pvi_core import (
    K_SATURACION,
    PESOS_FUENTE,
    PIEZAS_KIT,
    ResultadoAnalisis,
    analizar_corpus,
    es_productor_generico,
    recalcular_resultado_filtrado,
)

# --- CONFIGURACION DE PAGINA ---
st.set_page_config(
    page_title="Auditor PVI | OSINT & Social Engineering Defense",
    page_icon="🛡️",
    layout="wide",
)

# --- ESTILOS CSS AESTHETIC (CYBER GLASSMORPHISM & MODERN DASHBOARD ORIGINAL) ---
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

        /* Hero Banner con gradiente sutil y glassmorphism original */
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

        /* Grilla de las 5 dimensiones del pretexto con estilo Cyber Blue */
        .kit-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(195px, 1fr));
            gap: 12px;
            margin: 10px 0 16px 0;
        }
        .kit-card {
            border-radius: 12px;
            padding: 12px 14px;
            border: 1px solid rgba(148, 163, 184, 0.22);
            background: rgba(148, 163, 184, 0.05);
        }
        .kit-card.cubierta {
            border-color: rgba(56, 189, 248, 0.55);
            background: linear-gradient(135deg, rgba(2, 132, 199, 0.14) 0%, rgba(99, 102, 241, 0.08) 100%);
        }
        .kit-card.faltante {
            opacity: 0.55;
        }
        .kit-title {
            font-weight: 700;
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 4px;
        }
        .kit-desc {
            font-size: 0.76rem;
            opacity: 0.78;
            line-height: 1.35;
        }

        /* Barras personalizadas con gradiente original */
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
            word-break: break-word;
            overflow-wrap: anywhere;
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
    """Dataset controlado para demo y pruebas de regresion (incluye Secret Scanning)."""
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
                "Martin Gomez liderara el despliegue antes del cierre de trimestre. "
                "El nuevo Director de Finanzas encabeza el proceso de licitacion."
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
                f"Repositorio publico de {empresa} (deploy-scripts/notify.sh): "
                "Script de actualizacion del sistema interno para el proyecto de "
                "mantenimiento. SLACK_WEBHOOK=https://hooks.slack.com/services/T01AB/B02CD/efGhIjKl123 "
                "Endpoint: https://api.ejemplo.com/v2/admin"
            ),
            "url": "https://github.com/ejemplo/deploy-scripts",
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
            "fuente": "Metadatos PDF",
            "texto": (
                "Documento publico: Planilla Nominas 2025.\n"
                "Autor declarado en metadatos: Laura Perez.\n"
                "Planilla de nominas del area de Tesoreria, acceso al servidor interno por VPN."
            ),
            "url": "https://ejemplo.com/docs/Planilla_Nominas_2025.pdf",
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


# --- EXPORTADOR HTML AUTOCONTENIDO (Integrado de Social Eye) ---
def _recortar_texto(texto: str, max_chars: int = 380) -> str:
    """Limita la longitud de textos largos (como PDFs) para que las tablas sean legibles."""
    t = " ".join((texto or "").split())
    if len(t) <= max_chars:
        return t
    return t[:max_chars].rstrip(" ,;.") + "…"


def _formatear_actores(actores: list[str], max_items: int = 6) -> str:
    """Muestra hasta max_items actores para evitar listas interminables en PDFs."""
    if not actores:
        return "No especificados"
    visibles = actores[:max_items]
    resto = len(actores) - len(visibles)
    txt = ", ".join(visibles)
    return f"{txt} (+{resto} más)" if resto > 0 else txt


def procesar_archivos_subidos(archivos, empresa: str) -> list[dict]:
    """
    Procesa archivos cargados manualmente (.txt, .pdf, .docx, .xlsx) para
    permitir auditorias hibridas o pruebas controladas sin depender de la red.
    """
    items: list[dict] = []
    for arch in archivos or []:
        nombre = arch.name
        ext = nombre.lower().rsplit(".", 1)[-1] if "." in nombre else ""
        raw = arch.getvalue()

        if ext == "txt":
            texto_txt = raw.decode("utf-8", errors="ignore")
            for linea in texto_txt.splitlines():
                l = linea.strip()
                if not l or l.startswith("#"):
                    continue
                fuente_linea = "OSINT Redes / Dorking"
                if "|" in l:
                    partes = [p.strip() for p in l.split("|")]
                    if len(partes) >= 3:
                        _, fuente_raw, l = partes[0], partes[1], " | ".join(partes[2:])
                    elif len(partes) == 2:
                        fuente_raw, l = partes[0], partes[1]
                    else:
                        fuente_raw = ""
                    f_low = fuente_raw.lower()
                    if "noticia" in f_low or "news" in f_low:
                        fuente_linea = "Noticias / Blog Corporativo"
                    elif "git" in f_low:
                        fuente_linea = "GitHub / Codigo"
                    elif any(k in f_low for k in ("web", "blog", "equipo", "pagina", "página")):
                        fuente_linea = "Web Corporativa Directa"
                    elif "empleo" in f_low or "aviso" in f_low:
                        fuente_linea = "OSINT Redes / Dorking"

                # Reconoce lineas de metadatos o robots.txt dentro de un corpus .txt
                l_low = l.lower()
                if l_low.startswith("metadatos de ") or "author=" in l_low:
                    fuente_linea = "Metadatos PDF"
                    l = re.sub(
                        r"Metadatos de\s+([^\s:]+)\s*:",
                        r"Documento publico: \1.",
                        l,
                        flags=re.IGNORECASE,
                    )
                    l = re.sub(
                        r"\bauthor\s*=\s*([^;,\n]+)",
                        r"Autor declarado en metadatos: \1.",
                        l,
                        flags=re.IGNORECASE,
                    )
                elif "ruta desautorizada" in l_low or l_low.startswith("disallow:"):
                    fuente_linea = "Robots.txt / Sitemaps"

                # Garantiza atribucion al objetivo cuando el usuario sube un corpus manual
                texto_final = l if empresa.lower() in l.lower() else f"[{empresa}] {l}"
                items.append({
                    "fuente": fuente_linea,
                    "texto": texto_final,
                    "url": f"local://{nombre}",
                })

        elif ext == "pdf":
            try:
                reader = PdfReader(io.BytesIO(raw))
                meta = reader.metadata or {}
                autor = str(meta.get("/Author", "") or "").strip()
                creador = str(meta.get("/Creator", "") or "").strip()
                productor = str(meta.get("/Producer", "") or "").strip()
                texto_pag = ""
                for pag in reader.pages[:12]:
                    texto_pag += (pag.extract_text() or "") + "\n"
                nombre_limpio = re.sub(r"\.[A-Za-z0-9]{1,5}$", "", re.sub(r"[_%-]+", " ", nombre)).strip()
                partes_pdf = [f"Documento publico: {nombre_limpio} ({empresa})."]
                if autor:
                    partes_pdf.append(f"Autor declarado en metadatos: {autor}.")
                if creador and not es_productor_generico(creador):
                    partes_pdf.append(f"Software de creacion declarado: {creador}.")
                if productor and not es_productor_generico(productor):
                    partes_pdf.append(f"Productor del documento: {productor}.")
                if texto_pag.strip():
                    partes_pdf.append(" ".join(texto_pag.split())[:2500])
                items.append({
                    "fuente": "Metadatos PDF",
                    "texto": "\n".join(partes_pdf),
                    "url": f"local://{nombre}",
                })
            except Exception:
                continue

        elif ext in ("docx", "xlsx", "pptx"):
            try:
                if not zipfile.is_zipfile(io.BytesIO(raw)):
                    continue
                autor, texto_off = "", ""
                with zipfile.ZipFile(io.BytesIO(raw)) as zf:
                    nombres_zip = set(zf.namelist())
                    if "docProps/core.xml" in nombres_zip:
                        root = ET.fromstring(zf.read("docProps/core.xml"))
                        ns = {
                            "dc": "http://purl.org/dc/elements/1.1/",
                            "cp": "http://schemas.openxmlformats.org/package/2006/metadata/core-properties",
                        }
                        autor = (
                            root.findtext("dc:creator", default="", namespaces=ns)
                            or root.findtext("cp:lastModifiedBy", default="", namespaces=ns)
                            or ""
                        ).strip()
                    for doc_xml in ("word/document.xml", "xl/sharedStrings.xml"):
                        if doc_xml in nombres_zip:
                            root_txt = ET.fromstring(zf.read(doc_xml))
                            textos = [t.strip() for t in root_txt.itertext() if t and t.strip()]
                            texto_off = " ".join(textos)[:2500]
                            break
                nombre_limpio = re.sub(r"\.[A-Za-z0-9]{1,5}$", "", re.sub(r"[_%-]+", " ", nombre)).strip()
                partes_off = [f"Documento publico: {nombre_limpio} ({empresa})."]
                if autor:
                    partes_off.append(f"Autor declarado en metadatos: {autor}.")
                if texto_off:
                    partes_off.append(texto_off)
                items.append({
                    "fuente": "Metadatos PDF",
                    "texto": "\n".join(partes_off),
                    "url": f"local://{nombre}",
                })
            except Exception:
                continue

    return items


def generar_reporte_html(resultado: ResultadoAnalisis, empresa: str,
                         dominio: str, atestacion: str = "") -> str:
    """Genera un reporte HTML ejecutivo autocontenido listo para entregar o imprimir."""
    esc = html.escape
    color_pvi = (
        "#7a1626" if resultado.pvi >= 70
        else ("#c9a227" if resultado.pvi >= 35 else "#1d6b3a")
    )
    ang = int(min(100.0, max(0.0, resultado.pvi)) * 3.6)
    ahora = datetime.now().strftime("%Y-%m-%d %H:%M")
    atest_html = (
        f"<br><strong>Autorización declarada y registrada por el analista:</strong> {esc(atestacion)}"
        if atestacion else ""
    )

    piezas_html = ""
    for pieza, desc in PIEZAS_KIT.items():
        cub = pieza in resultado.piezas_cubiertas
        piezas_html += (
            f'<div class="pieza {"cub" if cub else "nocub"}">'
            f'<strong>{"●" if cub else "○"} {esc(pieza.upper())}</strong>'
            f'<small>{esc(desc)}</small></div>'
        )

    filas_html = ""
    col_sev = {"ALTO": "#7a1626", "MEDIO": "#c9a227", "BAJO": "#4a9d5b"}
    for h in resultado.hallazgos:
        c_sev = col_sev.get(h.severidad, "#555")
        piezas_str = ", ".join(h.piezas_kit) if h.piezas_kit else "-"
        actores_str = ", ".join(h.actores) if h.actores else "No especificados"
        if h.url:
            link_str = (
                f'<br><a class="src-link" href="{esc(h.url)}" target="_blank" '
                f'rel="noopener">↗ {esc(h.url)}</a>'
            )
        else:
            link_str = ""
        filas_html += f"""
        <tr>
            <td><span class="sev" style="background:{c_sev}">{esc(h.severidad)}</span></td>
            <td class="num"><b>+{h.impacto} pts</b><br><small>intr: {h.riesgo_intrinseco:.2f}</small></td>
            <td>{esc(h.fuente)}</td>
            <td class="exp">{esc(h.oracion)}<div class="meta-row"><b>Actores:</b> {esc(actores_str)} &middot; <b>Piezas:</b> {esc(piezas_str)}</div>{link_str}</td>
            <td>{esc(h.riesgo_desc)}</td>
            <td class="mit">{esc(h.mitigacion)}</td>
        </tr>"""

    return f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Reporte PVI - {esc(empresa)}</title>
<style>
  * {{ box-sizing:border-box; }}
  body {{ font-family:'Segoe UI',system-ui,sans-serif; margin:0; background:#f6f7fb; color:#1d2330; }}
  .wrap {{ max-width:1100px; margin:0 auto; padding:32px 20px 60px; }}
  header {{ display:flex; gap:28px; align-items:center; background:#fff; border:1px solid #e3e6ee; border-radius:14px; padding:24px 30px; }}
  .gauge {{ width:130px; height:130px; border-radius:50%; background:conic-gradient({color_pvi} {ang}deg, #e9ecf3 {ang}deg); display:grid; place-items:center; flex-shrink:0; }}
  .gauge-inner {{ width:96px; height:96px; border-radius:50%; background:#fff; display:grid; place-items:center; text-align:center; }}
  .gauge-inner b {{ font-size:28px; color:{color_pvi}; }}
  .nivel {{ display:inline-block; margin-top:8px; padding:4px 14px; border-radius:20px; color:#fff; font-weight:600; font-size:13px; background:{color_pvi}; }}
  h2 {{ font-size:14px; text-transform:uppercase; letter-spacing:.5px; color:#667; margin:28px 0 12px; }}
  .piezas-grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:10px; }}
  .pieza {{ background:#fff; border:1px solid #e3e6ee; border-radius:10px; padding:12px 14px; }}
  .pieza.cub {{ border-color:{color_pvi}; }}
  .pieza.nocub {{ opacity:.5; }}
  .pieza small {{ display:block; color:#667; font-size:11.5px; margin-top:4px; }}
  table {{ width:100%; border-collapse:collapse; background:#fff; border:1px solid #e3e6ee; border-radius:12px; overflow:hidden; font-size:13px; table-layout:fixed; }}
  col.c-sev {{ width:8%; }} col.c-imp {{ width:9%; }} col.c-fuente {{ width:13%; }}
  col.c-exp {{ width:34%; }} col.c-vec {{ width:18%; }} col.c-mit {{ width:18%; }}
  th, td {{ text-align:left; padding:11px 12px; border-bottom:1px solid #e3e6ee; vertical-align:top; word-break:break-word; overflow-wrap:anywhere; line-height:1.45; }}
  th {{ background:#eef1f7; font-size:11px; text-transform:uppercase; letter-spacing:.4px; color:#667; }}
  tr:last-child td {{ border-bottom:none; }}
  .sev {{ color:#fff; padding:2px 8px; border-radius:10px; font-size:11px; font-weight:600; white-space:nowrap; display:inline-block; }}
  .num {{ font-variant-numeric:tabular-nums; }}
  .meta-row {{ margin-top:6px; font-size:11.5px; color:#556; }}
  a.src-link {{ display:inline-block; margin-top:5px; color:#1d6b3a; font-size:11.5px; text-decoration:none; word-break:break-all; }}
  a.src-link:hover {{ text-decoration:underline; }}
  .mit {{ color:#1d6b3a; font-size:12.5px; }}
  .aviso {{ background:#fff7e6; border:1px solid #f0d9a8; color:#7a5a12; border-radius:10px; padding:12px 16px; font-size:12.5px; margin-top:18px; }}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <div class="gauge"><div class="gauge-inner"><div><b>{resultado.pvi}</b><br><small>/ 100</small></div></div></div>
    <div>
      <h1 style="margin:0 0 4px;font-size:22px;">Auditor PVI — Reporte Ejecutivo de Exposición OSINT</h1>
      <p style="margin:0;color:#667;">{esc(empresa)} &middot; {esc(dominio)} &middot; Confianza: {esc(resultado.confianza)}</p>
      <span class="nivel">{esc(resultado.estado)}</span>
    </div>
  </header>
  <h2>Dimensiones de Pretexto Expuestas &middot; {len(resultado.piezas_cubiertas)}/5</h2>
  <div class="piezas-grid">{piezas_html}</div>
  <h2>Hallazgos Conservados y Mitigaciones ({len(resultado.hallazgos)})</h2>
  <table>
    <colgroup>
      <col class="c-sev"><col class="c-imp"><col class="c-fuente">
      <col class="c-exp"><col class="c-vec"><col class="c-mit">
    </colgroup>
    <thead><tr><th>Sev.</th><th>Impacto</th><th>Fuente</th><th>Exposición</th><th>Vector Habilitado</th><th>Mitigación (Blue Team)</th></tr></thead>
    <tbody>{filas_html}</tbody>
  </table>
  <div class="aviso">
    <strong>Uso ético y responsable (Ley 25.326):</strong> Análisis OSINT estrictamente pasivo sobre fuentes públicas con fines defensivos. No constituye un guion operativo de ataque.{atest_html}
  </div>
  <p style="color:#667;font-size:12px;margin-top:18px;">
    Fórmula Exponencial: PVI = 100 × (1 − e^(−{resultado.pvi_bruto} / {K_SATURACION})) &middot; Generado el {ahora}.
  </p>
</div>
</body>
</html>"""


def generar_reporte_pdf_bytes(resultado: ResultadoAnalisis, empresa: str,
                              dominio: str, atestacion: str = "") -> bytes | None:
    """Genera el reporte en PDF en memoria usando reportlab (si esta instalado)."""
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    except ImportError:
        return None

    buf = io.BytesIO()
    styles = getSampleStyleSheet()
    normal = ParagraphStyle("n", parent=styles["Normal"], fontSize=7.5, leading=9.5)
    small = ParagraphStyle("s", parent=normal, fontSize=6.8, textColor=colors.HexColor("#556"))
    h1 = ParagraphStyle("h1", parent=styles["Title"], fontSize=16, spaceAfter=4)
    h2 = ParagraphStyle("h2", parent=styles["Normal"], fontSize=10, fontName="Helvetica-Bold", spaceBefore=10, spaceAfter=6)

    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=14 * mm, rightMargin=14 * mm, topMargin=14 * mm, bottomMargin=14 * mm)
    elems = [
        Paragraph(f"Auditor PVI — {html.escape(empresa)} ({html.escape(dominio)})", h1),
        Paragraph(
            f"<b>Índice PVI: {resultado.pvi} / 100 ({resultado.estado})</b> &middot; "
            f"Puntaje bruto: {resultado.pvi_bruto} pts &middot; "
            f"Dimensiones expuestas: {len(resultado.piezas_cubiertas)}/5 ({', '.join(resultado.piezas_cubiertas) or 'ninguna'})",
            normal,
        ),
        Spacer(1, 8),
        Paragraph("Matriz de Hallazgos y Contramedidas", h2),
    ]

    data = [[Paragraph(f"<b>{c}</b>", small) for c in ("Sev.", "Impacto", "Fuente", "Exposición", "Vector", "Mitigación")]]
    for h in resultado.hallazgos:
        oracion_pdf = _recortar_texto(h.oracion, max_chars=300)
        actores_pdf = _formatear_actores(h.actores, max_items=5)
        piezas_pdf = ", ".join(h.piezas_kit) if h.piezas_kit else "-"
        exp_pdf = (
            f"{html.escape(oracion_pdf)}<br/>"
            f"<font color='#556'><b>Actores:</b> {html.escape(actores_pdf)} | "
            f"<b>Piezas:</b> {html.escape(piezas_pdf)}</font>"
        )
        data.append([
            Paragraph(f"<b>{html.escape(h.severidad)}</b>", small),
            Paragraph(f"+{h.impacto}", normal),
            Paragraph(html.escape(h.fuente), small),
            Paragraph(exp_pdf, normal),
            Paragraph(html.escape(h.riesgo_desc), small),
            Paragraph(html.escape(h.mitigacion), small),
        ])

    tabla = Table(data, colWidths=[15 * mm, 14 * mm, 26 * mm, 52 * mm, 36 * mm, 39 * mm], repeatRows=1)
    tabla.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eef1f7")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d0d5dd")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    elems.append(tabla)
    elems.append(Spacer(1, 10))
    pie_txt = f"Generado el {datetime.now().strftime('%Y-%m-%d %H:%M')} · OSINT Pasivo Defensivo."
    if atestacion:
        pie_txt += f" · Autorización registrada: {html.escape(atestacion)}"
    elems.append(Paragraph(pie_txt, small))
    doc.build(elems)
    return buf.getvalue()


# --- CABECERA EJECUTIVA ORIGINAL ---
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
            "Solo Evidencia Manual (Archivos Locales)",
        ],
    )
    archivos_manuales = st.file_uploader(
        "Ingesta Manual de Evidencia (.txt, .pdf, .docx, .xlsx)",
        type=["txt", "pdf", "docx", "xlsx"],
        accept_multiple_files=True,
        help="Suba un corpus .txt (una publicación por línea) o documentos corporativos locales para extraer sus metadatos y analizar su contenido junto con la auditoría.",
    )
    st.divider()
    st.subheader("Ética y Privacidad (Ley 25.326)")
    enmascarar_input = st.checkbox(
        "Enmascarar datos personales (autores/emails)",
        value=False,
        help="Anonimiza nombres de empleados y correos electrónicos para cumplir con la Ley 25.326 de Protección de Datos Personales.",
    )
    autorizacion_input = st.checkbox(
        "Declaro contar con autorización para auditar este objetivo",
        value=True,
        help="Obligatorio para fuentes en vivo. Queda registrado con fecha y hora en el reporte exportado.",
    )
    st.divider()
    ejecutar = st.button("Ejecutar Evaluación PVI", type="primary", width="stretch")
    nueva_busqueda = st.button("Nueva Búsqueda", width="stretch")

if nueva_busqueda:
    import streamlit.components.v1 as components
    st.session_state.clear()
    components.html("<script>window.parent.location.reload();</script>", height=0)
    st.stop()

if ejecutar:
    if "en Vivo" in modo and not autorizacion_input:
        st.error(
            "⚠️ Para ejecutar la recolección OSINT en vivo debe confirmar explícitamente la "
            "**Declaración de Autorización Ética** en el panel lateral."
        )
        st.stop()

    with st.spinner("Ejecutando conectores OSINT y procesando lenguaje natural (spaCy)..."):
        datos: list[dict] = []
        estado_conn: list[dict] = []

        if "Simulación" in modo:
            datos = cargar_datos_simulacion(empresa_input)
            estado_conn = [
                {
                    "conector": "Simulación Controlada",
                    "estado": "ok",
                    "detalle": "Dataset determinista de validación",
                }
            ]
        elif "en Vivo" in modo:
            datos, estado_conn = recolectar_datos_reales(dominio_input, empresa_input)

        # Ingesta de archivos manuales (funciona sola o combinada con los otros modos)
        if archivos_manuales:
            items_manuales = procesar_archivos_subidos(archivos_manuales, empresa_input)
            datos.extend(items_manuales)
            estado_conn.append(
                {
                    "conector": "Ingesta Manual Local",
                    "estado": "ok" if items_manuales else "vacio",
                    "detalle": f"{len(items_manuales)} fragmentos/documentos extraídos de {len(archivos_manuales)} archivo(s)",
                }
            )

        if not datos:
            st.error(
                "No se obtuvieron datos para analizar. Si seleccionó 'Solo Evidencia Manual', "
                "asegúrese de adjuntar al menos un archivo (.txt, .pdf, .docx o .xlsx)."
            )
            st.stop()

        resultado_calc = analizar_corpus(
            datos,
            empresa_input,
            dominio_input,
            estado_conectores=estado_conn,
            enmascarar=enmascarar_input,
        )
        st.session_state["pvi_resultado_base"] = resultado_calc
        st.session_state["pvi_datos_raw"] = datos
        st.session_state["pvi_estado_conn"] = estado_conn
        st.session_state["pvi_empresa"] = empresa_input
        st.session_state["pvi_dominio"] = dominio_input
        st.session_state["pvi_atestacion"] = (
            datetime.now().strftime("%Y-%m-%d %H:%M") if autorizacion_input else ""
        )

if "pvi_resultado_base" not in st.session_state:
    st.info(
        "Configure la organización objetivo en el panel lateral y presione "
        "**Ejecutar Evaluación PVI** para iniciar la correlación de fuentes abiertas."
    )
else:
    resultado_base: ResultadoAnalisis = st.session_state["pvi_resultado_base"]
    datos = st.session_state["pvi_datos_raw"]
    estado = st.session_state["pvi_estado_conn"]
    empresa_actual = st.session_state["pvi_empresa"]
    dominio_actual = st.session_state["pvi_dominio"]
    atestacion_actual = st.session_state.get("pvi_atestacion", "")

    # --- FILTRO INTERACTIVO DE HALLAZGOS (Integrado de Social Eye) ---
    opciones_hallazgos = {
        i: f"#{i+1:02d} [{h.severidad}] {h.fuente} (+{h.impacto} pts) — {', '.join(h.terminos[:3])}"
        for i, h in enumerate(resultado_base.hallazgos)
    }
    with st.expander("🎛️ Depuración Interactiva de Hallazgos (Conservar / Excluir del PVI y Reportes)", expanded=False):
        st.caption(
            "Desmarque cualquier hallazgo que considere falso positivo o fuera de alcance; "
            "el Índice PVI, la cobertura del Kit de Pretexto y los reportes exportables se recalcularán al instante."
        )
        seleccionados = st.multiselect(
            "Hallazgos conservados en el cálculo:",
            options=list(opciones_hallazgos.keys()),
            default=list(opciones_hallazgos.keys()),
            format_func=lambda k: opciones_hallazgos[k],
        )

    if len(seleccionados) == len(resultado_base.hallazgos):
        resultado = resultado_base
    else:
        resultado = recalcular_resultado_filtrado(resultado_base, set(seleccionados))

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
        "Hallazgos Conservados",
        f"{len(resultado.hallazgos)} / {len(resultado_base.hallazgos)}",
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
                <h4>Índice de Vulnerabilidad a Pretextos (PVI) — {html.escape(empresa_actual)}</h4>
                <p>
                    Puntaje bruto acumulado: <strong>{resultado.pvi_bruto} pts</strong> &middot;
                    Curva exponencial: <code>PVI = 100 × (1 − e^(−bruto / {K_SATURACION}))</code> &middot;
                    Kit de Pretexto: <strong>{len(resultado.piezas_cubiertas)}/5 piezas</strong>
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

    # --- COBERTURA DE DIMENSIONES DE PRETEXTO ---
    st.subheader(f"Dimensiones de Pretexto Expuestas ({len(resultado.piezas_cubiertas)}/5)")
    tarjetas_kit = []
    for pieza, desc in PIEZAS_KIT.items():
        cub = pieza in resultado.piezas_cubiertas
        icono = "🔵" if cub else "⚪"
        clase = "cubierta" if cub else "faltante"
        tarjetas_kit.append(
            f'<div class="kit-card {clase}">'
            f'<div class="kit-title">{icono} {html.escape(pieza)}</div>'
            f'<div class="kit-desc">{html.escape(desc)}</div>'
            f'</div>'
        )
    st.markdown(f'<div class="kit-grid">{"".join(tarjetas_kit)}</div>', unsafe_allow_html=True)

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

    # --- BOTONES DE EXPORTACION A HTML Y PDF (Integrado de Social Eye) ---
    col_exp1, col_exp2, col_exp3 = st.columns([2, 1, 1])
    with col_exp1:
        if atestacion_actual:
            st.caption(f"✅ Autorización ética declarada y registrada en el reporte ({atestacion_actual}).")
    with col_exp2:
        html_reporte = generar_reporte_html(resultado, empresa_actual, dominio_actual, atestacion_actual)
        st.download_button(
            "📄 Descargar Reporte HTML",
            data=html_reporte.encode("utf-8"),
            file_name=f"reporte_pvi_{dominio_actual}.html",
            mime="text/html",
            width="stretch",
        )
    with col_exp3:
        pdf_bytes = generar_reporte_pdf_bytes(resultado, empresa_actual, dominio_actual, atestacion_actual)
        if pdf_bytes:
            st.download_button(
                "📕 Descargar Reporte PDF",
                data=pdf_bytes,
                file_name=f"reporte_pvi_{dominio_actual}.pdf",
                mime="application/pdf",
                width="stretch",
            )
        else:
            st.button(
                "📕 PDF (requiere reportlab)",
                disabled=True,
                help="Instale reportlab (`pip install reportlab`) para habilitar la exportación directa a PDF.",
                width="stretch",
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
        alerta_secreto = " 🔐 [SECRETO EXPUESTO]" if h.secretos else ""

        titulo_expander = (
            f"#{idx:02d} [{etiqueta_sev}]{alerta_secreto} {h.fuente}  |  "
            f"Impacto: +{h.impacto} pts (Riesgo intrínseco: {h.riesgo_intrinseco:.2f})  |  "
            f"Piezas: {', '.join(h.piezas_kit) or '-'}"
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
            piezas_txt = html.escape(", ".join(h.piezas_kit)) if h.piezas_kit else "Contexto general"
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
                        <span class="meta-label">Dimensiones / Categorías</span>
                        <code>{piezas_txt} ({cats_txt})</code>
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
    st.subheader("Trazabilidad Técnica, Marco Ético y Gobernanza del Modelo")
    tab_superficie, tab_conectores, tab_descartes, tab_metodologia = st.tabs(
        [
            f"Superficie Técnica ({len(resultado.reconocimiento_tecnico)})",
            f"Estado de Conectores ({len(estado)})",
            f"Auditoría de Filtrado ({len(resultado.descartes)})",
            "Especificación Metodológica y Legal",
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
            **1. Fórmula de Saturación Exponencial:**  
            `PVI = 100 × (1 − e^(−PVI_bruto / K))` con constante de calibración **K = {K_SATURACION}**.
            - **Riesgo Intrínseco (`0.00 – 0.99`):** Combinación probabilística de las categorías detectadas más bonificaciones por actor identificado (`PER`/`ORG`), identificador directo, sinergia de la *Tríada de Pretexto*, *Secret Scanning* y frescura temporal.
            - **Amortiguación por Fuente Repetida (`0.55^n`):** Impide que múltiples publicaciones de una misma fuente distorsionen el índice global.
            - **Cobertura del Kit del Pretexto (5 Piezas):** Evalúa qué partes del pretexto (*Identidad, Contexto, Canal, Jerga y Urgencia*) quedan expuestas frente a un atacante.

            **2. Marco Ético y Legal (Ley 25.326 — Protección de Datos Personales):**  
            - **OSINT Pasivo Puro:** Solo se consultan fuentes públicas abiertas sin interactuar ni alterar sistemas del objetivo.
            - **Anonimización / Enmascaramiento:** Permite ofuscar nombres propios y correos personales para evitar armar perfiles individuales.
            - **Atestación Auditable:** Toda ejecución en vivo exige declaración expresa de autorización, registrada con fecha y hora en los reportes exportados.
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
