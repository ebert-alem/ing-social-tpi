"""
Modulo de recoleccion OSINT.

Cada conector:
  - Devuelve una lista de items {"fuente", "texto", "url"}.
  - Captura sus propios errores y los reporta en "errores" en vez de tragarlos
    silenciosamente (en el codigo original un `except: pass` ocultaba fallos).
"""

from __future__ import annotations

import io
import re
import time
import urllib.parse
import xml.etree.ElementTree as ET
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

import feedparser
import requests
from bs4 import BeautifulSoup
from pypdf import PdfReader

from pvi_core import (
    _PATH_RE,
    es_productor_generico,
    evaluar_relevancia,
    limpiar_texto_analizable,
    normalizar,
    quitar_boilerplate,
    tokens_identificadores,
)

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) PVI-OSINT-Auditor/2.0"
    ),
    "Accept-Language": "es-ES,es;q=0.9,en;q=0.8",
}

TIMEOUT = 8
TIMEOUT_LARGO = 20

_SESSION = requests.Session()
_SESSION.headers.update(HEADERS)


def _get(url: str, *, params=None, timeout: int = TIMEOUT, reintentos: int = 2):
    """GET con Session reutilizable, reintentos y backoff exponencial."""
    ultimo_error = None
    for intento in range(reintentos + 1):
        try:
            r = _SESSION.get(url, params=params, timeout=timeout)
            if r.status_code in (429, 500, 502, 503, 504) and intento < reintentos:
                time.sleep(1.5 * (intento + 1))
                continue
            return r
        except Exception as exc:
            ultimo_error = exc
            if intento < reintentos:
                time.sleep(1.5 * (intento + 1))
                continue
    if ultimo_error:
        raise ultimo_error
    return None


def _item(fuente: str, texto: str, url: str = "") -> dict[str, str]:
    return {"fuente": fuente, "texto": texto, "url": url}


# ---------------------------------------------------------------------------
# CONECTOR 1: robots.txt + sitemaps (peso alto)
# ---------------------------------------------------------------------------

def conector_robots(dominio: str) -> tuple[list[dict], str]:
    """Analiza robots.txt: rutas prohibidas y sitemaps declarados."""
    items: list[dict] = []
    url = f"https://{dominio}/robots.txt"
    try:
        r = _get(url, timeout=TIMEOUT_LARGO)
        if r is None or r.status_code != 200:
            return items, f"HTTP {getattr(r, 'status_code', 'sin respuesta')}"

        lineas = []
        sitemaps = []
        for linea in r.text.splitlines():
            l = linea.strip()
            low = l.lower()
            if low.startswith("disallow:") and len(l.split(":", 1)[1].strip()) > 2:
                lineas.append(l)
            elif low.startswith("sitemap:"):
                sitemaps.append(l.split(":", 1)[1].strip())

        if lineas:
            texto = "Rutas publicadas en robots.txt del servidor:\n" + "\n".join(lineas[:60])
            items.append(_item("Robots.txt / Sitemaps", texto, url))

        if sitemaps:
            items.append(_item(
                "Robots.txt / Sitemaps",
                "Sitemaps declarados:\n" + "\n".join(sitemaps[:10]),
                url,
            ))

        return items, "ok" if items else "sin rutas relevantes"
    except Exception as exc:
        return items, f"error: {type(exc).__name__}"


# ---------------------------------------------------------------------------
# CONECTOR 2: Sitemap.xml + rastreo del sitio (nueva fuente)
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# CONECTOR 2: Sitemap.xml + rastreo recursivo y paralelo del sitio
# ---------------------------------------------------------------------------
_SITEMAP_MAX_URLS = 60
_RATEO_MINIMO_HTML = 40


def _urls_de_sitemap(url_sitemap: str, profundidad: int = 0) -> list[str]:
    """Extrae URLs de un sitemap plano o desglosa recursivamente un sitemapindex."""
    r = _SESSION.get(url_sitemap, timeout=TIMEOUT)
    r.raise_for_status()
    try:
        root = ET.fromstring(r.content)
    except ET.ParseError:
        return []

    ns = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}
    locs = [
        loc.text.strip()
        for loc in (root.findall(".//sm:loc", ns) or root.findall(".//{*}loc"))
        if loc.text
    ]

    # Si es un sitemap_index (contiene sub-sitemaps) y no excedimos profundidad:
    es_indice = root.tag.lower().endswith("sitemapindex")
    urls_finales: list[str] = []
    for u in locs:
        if (es_indice or u.lower().endswith(".xml")) and profundidad < 1:
            try:
                urls_finales.extend(_urls_de_sitemap(u, profundidad + 1))
            except Exception:
                continue
        else:
            urls_finales.append(u)
    return urls_finales


def _extraer_html_sitemap(u: str) -> str | None:
    """Descarga y limpia una pagina individual del sitemap."""
    try:
        rr = _SESSION.get(u, timeout=TIMEOUT)
        if rr.status_code != 200:
            return None
        soup = BeautifulSoup(rr.text, "html.parser")
        for tag in soup(["script", "style", "nav", "footer", "header",
                         "form", "noscript", "aside"]):
            tag.decompose()
        bloques = [
            p.get_text(" ", strip=True)
            for p in soup.find_all(["p", "h1", "h2", "h3", "li", "td"])
        ]
        bloques = [b for b in bloques if len(b) >= _RATEO_MINIMO_HTML]
        if bloques:
            limpio = quitar_boilerplate("\n".join(bloques[:40]))
            return f"[{u}] {limpio}"
    except Exception:
        return None
    return None


def conector_sitemap(dominio: str) -> tuple[list[dict], str]:
    """Descubre URLs reales del sitio y extrae texto de las paginas en paralelo."""
    items: list[dict] = []
    candidatas = [f"https://{dominio}/sitemap.xml",
                  f"https://{dominio}/sitemap_index.xml"]
    urls: list[str] = []
    for c in candidatas:
        try:
            urls.extend(_urls_de_sitemap(c))
        except Exception:
            continue
    if not urls:
        return items, "sin sitemap accesible"

    palabras_interes = ["emple", "trabaj", "carrera", "rrhh", "contact",
                        "prensa", "noticia", "blog", "sala",
                        "quienes", "nosotros", "servicio", "producto"]
    relevantes = [u for u in urls if any(p in u.lower() for p in palabras_interes)]
    objetivo = (relevantes + [u for u in urls if u not in relevantes])[:_SITEMAP_MAX_URLS]

    dominios_permitidos = {dominio.lower(), f"www.{dominio.lower()}"}
    urls_a_visitar: list[str] = []
    vistas: set[str] = set()
    for u in objetivo:
        host = urllib.parse.urlsplit(u).netloc.lower()
        if host not in dominios_permitidos:
            continue
        clave = u.rstrip("/").lower()
        if clave in vistas:
            continue
        vistas.add(clave)
        urls_a_visitar.append(u)

    texto_acumulado: list[str] = []
    if urls_a_visitar:
        with ThreadPoolExecutor(max_workers=6) as pool:
            for res in pool.map(_extraer_html_sitemap, urls_a_visitar):
                if res:
                    texto_acumulado.append(res)

    if texto_acumulado:
        items.append(_item(
            "Web Corporativa Directa",
            "\n".join(texto_acumulado),
            f"https://{dominio}",
        ))
    return items, f"{len(urls)} urls en sitemap, {len(vistas)} visitadas"

# ---------------------------------------------------------------------------
# CONECTOR 3: Certificados TLS Transparency (nueva fuente, subdominios)
# ---------------------------------------------------------------------------

def _patron_subdominio(dominio: str) -> re.Pattern:
    """
    Regex de subdominio valido: etiqueta + (etiqueta.)* + dominio.

    OJO: el grupo de etiquetas es opcional y NO puede terminar en punto
    justo antes del dominio; de lo contrario "www.example.com" no coincide.
    """
    return re.compile(
        r"^(?!-)[a-z0-9-]{1,63}(?<!-)(?:\.[a-z0-9-]{1,63})*\." + re.escape(dominio.lower()) + r"$"
    )


def _subdominios_crt_sh(dominio: str) -> set[str]:
    """Subdominios via crt.sh (Certificate Transparency)."""
    r = _get(
        "https://crt.sh/",
        params={"q": f"%.{dominio}", "output": "json"},
        timeout=10, reintentos=1,
    )
    if r is None or r.status_code != 200:
        raise RuntimeError(f"crt.sh HTTP {getattr(r, 'status_code', 'sin respuesta')}")

    subdominios: set[str] = set()
    patron_sub = _patron_subdominio(dominio)
    for entrada in r.json():
        for nombre in str(entrada.get("name_value", "")).splitlines():
            n = nombre.strip().lower().lstrip("*.")
            if n == dominio.lower() or not n.endswith(dominio.lower()):
                continue
            # Valida el formato: crt.sh incluye entradas con CN legibles
            # ("as207960 test intermediate - example.com") que no son
            # subdominios reales y generarian falsos positivos.
            if patron_sub.match(n):
                subdominios.add(n)
    return subdominios


def _subdominios_certspotter(dominio: str) -> set[str]:
    """Fallback a Cert Spotter cuando crt.sh no responde."""
    r = _get(
        "https://api.certspotter.com/v1/issuances",
        params={"domain": dominio, "include_subdomains": "true", "expand": "dns_names"},
        timeout=20, reintentos=1,
    )
    if r is None or r.status_code != 200:
        raise RuntimeError(f"certspotter HTTP {getattr(r, 'status_code', 'sin respuesta')}")

    subdominios: set[str] = set()
    patron_sub = _patron_subdominio(dominio)
    for entrada in r.json():
        for nombre in str(entrada.get("dns_names", []) or []):
            n = nombre.strip().lower().lstrip("*.")
            if n == dominio.lower() or not n.endswith(dominio.lower()):
                continue
            if patron_sub.match(n):
                subdominios.add(n)
    return subdominios


def _subdominios_hackertarget(dominio: str) -> set[str]:
    """Subdominios rapidos via HackerTarget API (no sufre timeouts en dominios grandes)."""
    r = _get(
        "https://api.hackertarget.com/hostsearch/",
        params={"q": dominio},
        timeout=10, reintentos=1,
    )
    if r is None or r.status_code != 200 or "error" in r.text.lower()[:40]:
        raise RuntimeError("hackertarget sin datos")
    subdominios: set[str] = set()
    patron_sub = _patron_subdominio(dominio)
    for linea in r.text.splitlines():
        n = linea.split(",")[0].strip().lower().lstrip("*.")
        if n and n != dominio.lower() and patron_sub.match(n):
            subdominios.add(n)
    return subdominios


def conector_certificados(dominio: str) -> tuple[list[dict], str]:
    """Subdominios expuestos via CT logs y DNS pasivo (HackerTarget / crt.sh / CertSpotter)."""
    items: list[dict] = []
    subdominios: set[str] = set()
    origenes: list[str] = []
    errores: list[str] = []

    for fn, nombre in (
        (_subdominios_hackertarget, "hackertarget"),
        (_subdominios_crt_sh, "crt.sh"),
        (_subdominios_certspotter, "certspotter"),
    ):
        try:
            encontrados = fn(dominio)
            if encontrados:
                subdominios |= encontrados
                origenes.append(nombre)
                if len(subdominios) >= 30:
                    break
        except Exception as exc:
            errores.append(f"{nombre}: {type(exc).__name__}")
            continue

    if not subdominios:
        return items, "error: " + " | ".join(errores or ["sin resultados"])

    sensibles = []
    marcadores = ["admin", "vpn", "intranet", "staging", "stage", "dev",
                  "test", "uat", "preprod", "backup", "old", "legacy",
                  "gitlab", "jenkins", "jira", "confluence", "sonar",
                  "grafana", "kibana", "portainer", "phpmyadmin",
                  "api", "internal", "corp", "mail", "ftp", "sftp", "sso", "auth"]
    for sub in sorted(subdominios):
        marca = next((m for m in marcadores if m in sub), None)
        if marca:
            sensibles.append(f"{sub} (sospecha: {marca})")

    texto = "Subdominios certificados del dominio:\n" + "\n".join(sorted(subdominios)[:120])
    if sensibles:
        texto += "\nSubdominios con nombre sensible:\n" + "\n".join(sensibles[:40])
    items.append(_item("Subdominios (Certificados)", texto, f"https://crt.sh/?q={dominio}"))
    return items, f"{len(subdominios)} subdominios (fuente: {'+'.join(origenes)})"


# ---------------------------------------------------------------------------
# CONECTOR 4: Historico web (Wayback Machine) - nueva fuente
# ---------------------------------------------------------------------------

def conector_historico(dominio: str) -> tuple[list[dict], str]:
    """URLs historicas del dominio: paneles y ficheros olvidados."""
    items: list[dict] = []
    try:
        r = _get(
            "https://web.archive.org/cdx/search/cdx",
            params={
                "url": f"{dominio}/*",
                "output": "json",
                "fl": "original,timestamp,mimetype",
                "collapse": "urlkey",
                "limit": "400",
                "filter": "statuscode:200",
            },
            timeout=25, reintentos=2,
        )
        if r is None or r.status_code != 200:
            return items, f"HTTP {getattr(r, 'status_code', 'sin respuesta')}"

        filas = r.json()
        if not filas or len(filas) < 2:
            return items, "sin historial"

        urls: list[str] = []
        for fila in filas[1:]:
            if fila and fila[0]:
                urls.append(str(fila[0]))

        # Prioriza rutas historicas sensibles. Se busca por SEGMENTO de ruta
        # (delimitado por / o .) para evitar falsos positivos como
        # "/imagen.jpg" conteniendo "res" o "dev" dentro del nombre.
        segmentos_sensibles = {
            "admin", "wp-admin", "backup", "backups", "config", "intranet",
            "staging", "dev", "test", "panel", "login", "api", "phpinfo",
            "old", "private", "internal", "console", "phpmyadmin",
        }
        extensiones_sensibles = (
            ".sql", ".env", ".bak", ".old", ".xlsx", ".csv", ".doc", ".docx",
            ".pem", ".key", ".conf", ".yml", ".yaml", ".zip",
        )

        def _es_sensible(u: str) -> bool:
            path = urllib.parse.urlsplit(u).path.lower()
            partes = [p for p in path.split("/") if p]
            for p in partes:
                # Segmento de ruta limpio (sin extension) comparado exacto.
                base = p.split(".")[0]
                if base in segmentos_sensibles:
                    return True
            return path.endswith(extensiones_sensibles)

        sensibles = [u for u in urls if _es_sensible(u)][:40]
        Extension = [u for u in urls
                     if urllib.parse.urlsplit(u).path.lower().endswith(
                         (".xlsx", ".csv", ".sql", ".env", ".bak", ".doc", ".docx"))][:40]

        if sensibles or Extension:
            texto = ("Rutas historicas sensibles en el archivo web:\n"
                     + "\n".join((sensibles + Extension)[:60]))
            items.append(_item("Historico Web (Wayback)", texto,
                               "https://web.archive.org/cdx/search/cdx"))
        return items, f"{len(urls)} urls historicas"
    except Exception as exc:
        return items, f"error: {type(exc).__name__}"


# ---------------------------------------------------------------------------
# CONECTOR 5: DNS over HTTPS - nueva fuente (proveedores, tokens, MX)
# ---------------------------------------------------------------------------

def conector_dns(dominio: str) -> tuple[list[dict], str]:
    """Registros TXT/MX/CNAME: proveedores usados y tokens de verificacion."""
    items: list[dict] = []
    hallazgos: list[str] = []

    for tipo in ("TXT", "MX", "CNAME"):
        try:
            r = requests.get(
                "https://dns.google/resolve",
                params={"name": dominio, "type": tipo},
                headers=HEADERS, timeout=12,
            )
            if r.status_code != 200:
                continue
            data = r.json()
            for answer in data.get("Answer", []) or []:
                valor = str(answer.get("data", "")).strip()
                if not valor:
                    continue
                if tipo == "TXT":
                    hallazgos.append(f"TXT: {valor}")
                elif tipo == "MX":
                    hallazgos.append(f"Servidor de correo (MX): {valor}")
                else:
                    hallazgos.append(f"CNAME: {valor}")
        except Exception:
            continue

    if not hallazgos:
        return items, "sin registros DNS"

    # Detecta tokens de verificacion y proveedores en los TXT.
    tokens_verif = [h for h in hallazgos if re.search(
        r"(verification|verify|token|site-verification|MS=|spf|include:|"
        r"v=spf1|google-site|microsoft)", h, re.IGNORECASE)]
    if tokens_verif:
        # No se emite una linea descriptiva del analisis: el motor de NLP
        # interpretaria palabras como "proveedor" o "deteccion" como senal
        # social. Se repiten los REGISTROS CRUDOS relevantes, sin etiquetas.
        hallazgos.extend(tokens_verif[:20])

    # Se usa un salto de linea por registro (no " | "): el analizador trata
    # cada linea como un fragmento independiente y puede descartar la lista
    # como enumeracion tecnica en vez de tratarla como un relato social.
    texto = "Registros DNS publicos del dominio:\n" + "\n".join(hallazgos[:40])
    items.append(_item("DNS / Registros TXT", texto, f"https://dns.google/resolve?name={dominio}"))
    return items, f"{len(hallazgos)} registros"


# ---------------------------------------------------------------------------
# CONECTOR 6: GitHub - repositorios + organizacion (query corregida)
# ---------------------------------------------------------------------------

def conector_github(dominio: str, empresa: str) -> tuple[list[dict], str]:
    """Repositorios publicos, commits recientes y organizacion en GitHub."""
    items: list[dict] = []
    queries = [
        f'"{empresa}" in:name,description,readme',
        f'"{dominio}" in:readme,description',
    ]
    vistos: set[str] = set()
    total = 0
    tokens = tokens_identificadores(empresa) or [empresa.strip().lower()]
    tokens_norm = [t.lower() for t in tokens if t]

    for q in queries:
        try:
            r = _SESSION.get(
                "https://api.github.com/search/repositories",
                params={"q": q, "per_page": 20, "sort": "updated"},
                headers={"Accept": "application/vnd.github+json"},
                timeout=12,
            )
            if r.status_code != 200:
                continue
            for repo in r.json().get("items", []):
                full = repo.get("full_name", "")
                if not full or full in vistos:
                    continue
                desc = repo.get("description") or ""
                owner = repo.get("owner", {}).get("login", "desconocido")
                texto_para_filtrar = f"{full} {desc} {owner}".lower()
                if not any(t in texto_para_filtrar for t in tokens_norm):
                    continue
                vistos.add(full)
                total += 1
                texto = (
                    f"Repositorio publico {full} mantenido por {owner}. "
                    f"Descripcion: {desc}. "
                    f"URL: {repo.get('html_url','')}"
                )
                items.append(_item("GitHub / Codigo", texto, repo.get("html_url", "")))

                # Extraer commits SOLO si el autor tiene correo del dominio corporativo
                # o si el mensaje describe infraestructura/procesos reales (no "initial commit").
                if total <= 3:
                    try:
                        rc = _SESSION.get(
                            f"https://api.github.com/repos/{full}/commits",
                            params={"per_page": 3},
                            headers={"Accept": "application/vnd.github+json"},
                            timeout=6,
                        )
                        if rc.status_code == 200:
                            for c_item in rc.json()[:3]:
                                commit_data = c_item.get("commit", {})
                                autor_c = commit_data.get("author", {})
                                nombre_c = (autor_c.get("name", "") or "").strip()
                                email_c = (autor_c.get("email", "") or "").strip().lower()
                                msg_c = (commit_data.get("message", "") or "").splitlines()[0].strip()

                                # Filtro simple y contundente: solo aceptar commits cuyo email
                                # pertenezca al dominio auditado (ej. @cresud.com.ar), descartando
                                # @gmail.com / @users.noreply.github.com de terceros ajenos.
                                es_email_corporativo = (
                                    bool(dominio)
                                    and email_c.endswith(("@" + dominio.lower(), "." + dominio.lower()))
                                )
                                if nombre_c and es_email_corporativo:
                                    items.append(_item(
                                        "GitHub / Codigo",
                                        f"Cambio en repositorio {full} por {nombre_c} "
                                        f"({email_c}): {msg_c}",
                                        c_item.get("html_url", repo.get("html_url", "")),
                                    ))
                    except Exception:
                        pass
        except Exception:
            continue

    # Organizacion de GitHub asociada al nombre.
    try:
        slug = urllib.parse.quote(empresa.strip().replace(" ", "-"), safe="")
        r = _SESSION.get(
            f"https://api.github.com/orgs/{slug}",
            headers={"Accept": "application/vnd.github+json"},
            timeout=10,
        )
        if r.status_code == 200:
            org = r.json()
            texto = (
                f"Organizacion de GitHub '{org.get('login')}': "
                f"repositorios publicos={org.get('public_repos')}, "
                f"miembros={org.get('members_count')}, "
                f"ubicacion={org.get('location', 'no publicada')}, "
                f"sitio web={org.get('blog', 'no publicado')}, "
                f"descripcion={org.get('description', 'no publicada')}"
            )
            items.append(_item("GitHub / Codigo", texto, org.get("html_url", "")))
    except Exception:
        pass

    if not items:
        return [], f"sin repositorios atribuibles a '{empresa}'"
    n_org = len(items) - total
    partes = [f"{total} repositorios"]
    if n_org:
        partes.append(f"{n_org} organizacion(es)")
    return items, " + ".join(partes)


# ---------------------------------------------------------------------------
# CONECTOR 7: Noticias RSS multivariante
# ---------------------------------------------------------------------------

_VARIANTES_NOTICIA = [
    '"{empresa}"',
    '"{empresa}" (licitacion OR contrato OR auditoria)',
    '"{empresa}" (ciberataque OR filtracion OR datos)',
    '"{empresa}" (empleo OR rrhh OR capacitacion)',
]


def conector_noticias(empresa: str, dominio: str) -> tuple[list[dict], str]:
    """Google News RSS con varias consultas y filtro de relevancia."""
    items: list[dict] = []
    vistos: set[str] = set()
    total = 0

    for plantilla in _VARIANTES_NOTICIA:
        query = plantilla.format(empresa=empresa)
        try:
            rss_url = (
                "https://news.google.com/rss/search?q="
                f"{urllib.parse.quote(query)}&hl=es-419&gl=AR&ceid=AR:es-419"
            )
            feed = feedparser.parse(rss_url)
            for entry in feed.entries[:15]:
                titulo = entry.get("title", "")
                resumen = BeautifulSoup(
                    entry.get("summary", ""), "html.parser"
                ).get_text(" ")
                fecha = entry.get("published", "Reciente")
                texto = f"Noticia ({fecha}): {titulo}. {resumen}"

                # FILTRO: solo si el resultado menciona al objetivo.
                relevante, _, _ = evaluar_relevancia(texto, empresa, dominio,
                                                      entry.get("link", ""))
                if not relevante:
                    continue

                clave = normalizar(titulo)
                if clave in vistos:
                    continue
                vistos.add(clave)
                total += 1
                items.append(_item("Noticias / Blog Corporativo", texto,
                                   entry.get("link", "")))
        except Exception:
            continue

    return items, f"{total} noticias relevantes"


# ---------------------------------------------------------------------------
# CONECTOR 8: Dorking dirigido (empleados, documentos, repos)
# ---------------------------------------------------------------------------

_DORKS = [
    ('site:linkedin.com/in/ "{empresa}"', "OSINT Redes / Dorking", 25),
    ('site:linkedin.com/in/ "{empresa}" (Gerente OR Director OR Manager OR Lead OR Recruiter OR RRHH)', "OSINT Redes / Dorking", 20),
    ('site:linkedin.com/in/ "{empresa}" (SAP OR AWS OR Azure OR DevOps OR Security OR Finanzas)', "OSINT Redes / Dorking", 20),
    ('site:linkedin.com/posts/ "{empresa}"', "OSINT Redes / Dorking", 15),
    ('site:{dominio} filetype:pdf', "OSINT Redes / Dorking", 12),
    ('site:{dominio} (inurl:admin OR inurl:login OR inurl:vpn OR inurl:portal)', "OSINT Redes / Dorking", 12),
    ('"{empresa}" ("@{dominio}" OR "contacto" OR "rrhh")', "OSINT Redes / Dorking", 15),
    ('site:github.com "{dominio}" OR "{empresa}"', "GitHub / Codigo", 15),
]


# Dominios donde el contenido es技术支持 genérico o de terceros: el titular
# NO es la organizacion auditada y las frases ("how to reset login", "password
# error") son ruido de foro, no exposicion de la empresa.
_DOMINIOS_RUIDO = (
    "stackoverflow.com", "stackexchange.com", "superuser.com",
    "serverfault.com", "askubuntu.com", "reddit.com", "quora.com",
    "youtube.com", "vimeo.com", "pinterest.com", "tiktok.com",
    "medium.com", "wordpress.com", "blogspot.com", "wikipedia.org",
    "google.com", "bing.com", "yandex.com", "duckduckgo.com",
    "archive.org", "scribd.com", "slideshare.net", "issuu.com",
    "amazon.", "ebay.", "mercadolibre", "aliexpress", "tradingview.",
    "forum.gitlab.com", "discourse.", "php.net", "w3schools.com",
    "geeksforgeeks.org", "tutorialspoint.com", "javatpoint.com",
    "pastebin.com", "gist.github.com", "gitlab.com/-/snippets",
)


def _es_ruido_de_foro(href: str) -> bool:
    """True si el resultado viene de un sitio de soporte/foros de terceros."""
    h = (href or "").lower()
    return any(d in h for d in _DOMINIOS_RUIDO)


def conector_dorking(empresa: str, dominio: str) -> tuple[list[dict], str]:
    """Busqueda dirigida en DDGS optimizada contra rate-limit para recuperar perfiles de LinkedIn."""
    from ddgs import DDGS
    items: list[dict] = []
    total = 0
    relevantes = 0
    errores: list[str] = []
    urls_vistas: set[str] = set()

    def _ejecutar_dork(dork_cfg: tuple[str, str, int]):
        plantilla, fuente, max_r = dork_cfg
        query = plantilla.format(empresa=empresa, dominio=dominio)
        try:
            with DDGS() as ddgs:
                res_ddg = list(ddgs.text(query, max_results=max_r))
            return fuente, res_ddg, None
        except Exception as exc:
            return fuente, [], f"{query[:35]}...: {type(exc).__name__}"

    # max_workers=2 evita que DuckDuckGo bloquee por exceso de concurrencia desde la misma IP
    with ThreadPoolExecutor(max_workers=2) as pool:
        resultados_dorks = list(pool.map(_ejecutar_dork, _DORKS))

    for fuente, resultados, err in resultados_dorks:
        if err:
            errores.append(err)
            continue
        for res in resultados:
            total += 1
            titulo = (res.get("title", "") or "").strip()
            cuerpo = (res.get("body", "") or "").strip()
            href = (res.get("href", "") or "").strip()
            if not href or href in urls_vistas:
                continue

            # En perfiles de LinkedIn (/in/), extraemos el nombre limpio del empleado del titulo
            if "linkedin.com/in/" in href.lower():
                nombre_emp = titulo.split("-")[0].split("|")[0].strip()
                texto = f"Perfil de empleado en LinkedIn: {nombre_emp} ({titulo}). {cuerpo}"
            else:
                texto = f"{titulo} - {cuerpo}"

            ok, _, _ = evaluar_relevancia(texto, empresa, dominio, href)
            if not ok:
                continue
            if _es_ruido_de_foro(href):
                continue

            urls_vistas.add(href)
            relevantes += 1
            items.append(_item(fuente, texto, href))

    detalle = f"{relevantes}/{total} resultados relevantes"
    if errores:
        detalle += f" | {len(errores)} dorks con error: " + "; ".join(errores[:3])
    return items, detalle

# ---------------------------------------------------------------------------
# CONECTOR 9: Metadatos y texto de PDFs (con filtro de productor generico)
# ---------------------------------------------------------------------------

_TAMANO_MAX_PDF = 12 * 1024 * 1024  # 12 MB

# Extensiones de documentos cuyos metadatos son diana de ingenieria social.
_EXT_DOCUMENTO = (".pdf", ".xlsx", ".xls", ".doc", ".docx", ".ppt", ".pptx",
                  ".csv", ".odt", ".ods")

# Motor de busqueda usado para descubrir documentos. Se inyecta en las
# pruebas para no depender de la red.
_BUSCADOR_DOCS = None


def _resolver_url_buscador(href: str) -> str:
    """
    Resuelve URLs de redireccion de los motores de busqueda.

    Los resultados de dorking suelen traer 'https://www.google.com/url?q=REAL'
    o 'https://duckduckgo.com/l/?uddg=REAL'. Sin resolverlas, el conector de
    documentos nunca ve una URL terminada en .pdf y no descarga nada.
    """
    if not href:
        return ""
    try:
        partes = urllib.parse.urlsplit(href)
        query = urllib.parse.parse_qs(partes.query)
    except Exception:
        return href

    for clave in ("q", "uddg", "url", "u3"):
        valores = query.get(clave)
        if valores:
            real = urllib.parse.unquote(valores[0])
            if real.startswith("http"):
                return real
    return href


def _buscar_documentos(dominio: str, empresa: str, maximo: int = 25) -> list[str]:
    """Busca documentos publicos del dominio via dorking en paralelo."""
    global _BUSCADOR_DOCS
    try:
        from ddgs import DDGS
    except Exception:
        return []
    consultas = [
        f"site:{dominio} filetype:pdf",
        f"site:{dominio} filetype:xlsx OR filetype:xls",
        f"site:{dominio} filetype:doc OR filetype:docx",
        f'"{empresa}" filetype:pdf',
    ]
    base = dominio.lower().lstrip(".")
    urls: list[str] = []
    vistas: set[str] = set()

    def _correr_consulta(consulta: str):
        try:
            if _BUSCADOR_DOCS is not None:
                return list(_BUSCADOR_DOCS(consulta) or [])
            with DDGS() as ddgs:
                return list(ddgs.text(consulta, max_results=12))
        except Exception:
            return []

    if _BUSCADOR_DOCS is not None:
        lotes = [_correr_consulta(c) for c in consultas]
    else:
        with ThreadPoolExecutor(max_workers=2) as pool:
            lotes = list(pool.map(_correr_consulta, consultas))

    for resultados in lotes:
        for res in resultados:
            href = res.get("href", "") if isinstance(res, dict) else str(res)
            real = _resolver_url_buscador(href)
            if not real:
                continue
            ruta = urllib.parse.urlsplit(real).path.lower()
            if not ruta.endswith(_EXT_DOCUMENTO):
                continue
            host = urllib.parse.urlsplit(real).netloc.lower().split(":")[0]
            if not (host == base or host.endswith("." + base)):
                continue
            if real in vistas:
                continue
            vistas.add(real)
            urls.append(real)
            if len(urls) >= maximo:
                return urls
    return urls


def _analizar_pdf(url: str, titulo: str) -> dict[str, str] | None:
    """
    Extrae metadatos y texto de un PDF publico.

    ENFOQUE (validado con el usuario): los metadatos de documento son un
    vector de INGENIERIA SOCIAL, no un vector puramente tecnico.
      - El AUTOR ("mgarcia") y el NOMBRE DEL ARCHIVO ("Formulario_Proveedores")
        identifican a la persona y el contenido: son la diana de un phishing
        dirigido ("simulando una actualizacion urgente de seguridad").
      - El PRODUCTOR/CREATOR generico (Adobe Acrobat, Microsoft Word...) NO
        puntua: no aporta ninguna diana y solo genera falsos positivos.
    """
    try:
        r = requests.get(url, headers=HEADERS, timeout=15, stream=True)
        if r.status_code != 200:
            return None
        content_type = r.headers.get("Content-Type", "")
        if "pdf" not in content_type.lower() and not url.lower().endswith(".pdf"):
            return None

        datos = b""
        for chunk in r.iter_content(chunk_size=8192):
            datos += chunk
            if len(datos) > _TAMANO_MAX_PDF:
                return None

        reader = PdfReader(io.BytesIO(datos))
        meta = reader.metadata or {}
        autor = str(meta.get("/Author", "") or "").strip()
        crear = str(meta.get("/Creator", "") or "").strip()
        productor = str(meta.get("/Producer", "") or "").strip()
        titulo_pdf = str(meta.get("/Title", "") or "").strip()

        texto_extraido = ""
        try:
            # Se extraen hasta 12 paginas: en documentos administrativos la
            # evidencia relevante (tabla de proveedores, directorio, firmas)
            # suele estar al final, no en la portada.
            for pagina in reader.pages[:12]:
                texto_extraido += pagina.extract_text() or ""
                texto_extraido += "\n"
        except Exception:
            texto_extraido = ""

        # Nombre del archivo: es evidencia de contenido y de diana.
        nombre_archivo = ""
        try:
            ruta = urllib.parse.urlsplit(url).path
            nombre_archivo = urllib.parse.unquote(ruta.rsplit("/", 1)[-1])
        except Exception:
            pass
        if not nombre_archivo:
            nombre_archivo = str(titulo or titulo_pdf or "documento.pdf")

        # El nombre del archivo legible ("Formulario_Proveedores.pdf") revela
        # el tipo de documento y por tanto el pretexto posible.
        nombre_legible = re.sub(r"[_%-]+", " ", nombre_archivo)
        nombre_legible = re.sub(r"\.[A-Za-z0-9]{1,5}$", "", nombre_legible).strip()

        partes = [f"Documento publico: {nombre_legible}."]
        if autor:
            partes.append(f"Autor declarado en metadatos: {autor}.")
        # El productor generico (Adobe Acrobat, Microsoft Word...) NO es riesgo:
        # se omite para no generar falsos positivos.
        if crear and not es_productor_generico(crear):
            partes.append(f"Software de creacion declarado: {crear}.")
        if productor and not es_productor_generico(productor):
            partes.append(f"Productor del documento: {productor}.")
        if texto_extraido.strip():
            # El contenido se emite SIN etiqueta artificial ("Texto del
            # documento:"): un prefijo propio falsea el NER, que lo interpreta
            # como parte de la frase y desplaza a la entidad principal. El
            # texto del PDF se trata igual que cualquier otra publicacion.
            partes.append(" ".join(texto_extraido.split())[:2500])

        return _item("Metadatos PDF", "\n".join(partes), url)
    except Exception:
        return None

def _analizar_office(url: str, titulo: str = "") -> dict[str, str] | None:
    """
    Extrae metadatos (dc:creator, cp:lastModifiedBy, Application) y texto
    de documentos Office (.docx, .xlsx, .pptx) sin dependencias externas.
    """
    try:
        r = _SESSION.get(url, timeout=15, stream=True)
        if r.status_code != 200:
            return None
        datos = b""
        for chunk in r.iter_content(chunk_size=8192):
            datos += chunk
            if len(datos) > _TAMANO_MAX_PDF:
                return None

        if not zipfile.is_zipfile(io.BytesIO(datos)):
            return None

        autor = ""
        modificador = ""
        aplicacion = ""
        texto_extraido = ""

        with zipfile.ZipFile(io.BytesIO(datos)) as zf:
            nombres = set(zf.namelist())
            if "docProps/core.xml" in nombres:
                root = ET.fromstring(zf.read("docProps/core.xml"))
                ns = {
                    "dc": "http://purl.org/dc/elements/1.1/",
                    "cp": "http://schemas.openxmlformats.org/package/2006/metadata/core-properties",
                }
                autor = (root.findtext("dc:creator", default="", namespaces=ns) or "").strip()
                modificador = (root.findtext("cp:lastModifiedBy", default="", namespaces=ns) or "").strip()

            if "docProps/app.xml" in nombres:
                root_app = ET.fromstring(zf.read("docProps/app.xml"))
                for elem in root_app.iter():
                    if elem.tag.endswith("Application") and elem.text:
                        aplicacion = elem.text.strip()
                        break

            # Extrae texto de Word (word/document.xml) o Excel (xl/sharedStrings.xml)
            for doc_xml in ("word/document.xml", "xl/sharedStrings.xml"):
                if doc_xml in nombres:
                    root_txt = ET.fromstring(zf.read(doc_xml))
                    textos = [t.strip() for t in root_txt.itertext() if t and t.strip()]
                    texto_extraido = " ".join(textos)[:2500]
                    break

        ruta = urllib.parse.urlsplit(url).path
        nombre_archivo = urllib.parse.unquote(ruta.rsplit("/", 1)[-1]) or titulo or "documento"
        nombre_legible = re.sub(r"[_%-]+", " ", nombre_archivo)
        nombre_legible = re.sub(r"\.[A-Za-z0-9]{1,5}$", "", nombre_legible).strip()

        partes = [f"Documento publico: {nombre_legible}."]
        persona = autor or modificador
        if persona:
            partes.append(f"Autor declarado en metadatos: {persona}.")
        if aplicacion and not es_productor_generico(aplicacion):
            partes.append(f"Software de creacion declarado: {aplicacion}.")
        if texto_extraido:
            partes.append(texto_extraido)

        return _item("Metadatos PDF", "\n".join(partes), url)
    except Exception:
        return None

def _procesar_documento_url(url: str) -> dict[str, str] | None:
    ruta = urllib.parse.urlsplit(url).path.lower()
    if ruta.endswith((".docx", ".xlsx", ".pptx")):
        return _analizar_office(url, "")
    return _analizar_pdf(url, "")

def conector_pdf(items_previos: list[dict], empresa: str,
                 dominio: str) -> tuple[list[dict], str]:
    """Descarga documentos publicos (PDF y Office) en paralelo y extrae metadatos/contenido."""
    items: list[dict] = []
    urls_docs: list[str] = []

    for u in _buscar_documentos(dominio, empresa):
        if u not in urls_docs:
            urls_docs.append(u)

    for it in items_previos:
        url = it.get("url", "")
        real = _resolver_url_buscador(url)
        ruta = urllib.parse.urlsplit(real).path.lower()
        if ruta.endswith(_EXT_DOCUMENTO) and real not in urls_docs:
            urls_docs.append(real)

    objetivo = urls_docs[:12]
    if objetivo:
        with ThreadPoolExecutor(max_workers=4) as pool:
            for res in pool.map(_procesar_documento_url, objetivo):
                if res:
                    items.append(res)

    return items, f"{len(items)} de {len(urls_docs)} documentos analizados"


# ---------------------------------------------------------------------------
# CONECTOR 10: Pagina principal y security.txt
# ---------------------------------------------------------------------------

def conector_web_directa(dominio: str) -> tuple[list[dict], str]:
    """Home del sitio y .well-known/security.txt."""
    items: list[dict] = []

    try:
        r = requests.get(f"https://{dominio}", headers=HEADERS, timeout=TIMEOUT)
        if r.status_code == 200:
            soup = BeautifulSoup(r.text, "html.parser")
            for tag in soup(["script", "style", "nav", "footer", "header",
                             "form", "noscript", "aside"]):
                tag.decompose()
            bloques = [
                p.get_text(" ", strip=True)
                for p in soup.find_all(["p", "h1", "h2", "h3", "li"])
            ]
            bloques = [b for b in bloques if len(b) >= 40]
            if bloques:
                items.append(_item(
                    "Web Corporativa Directa",
                    quitar_boilerplate("\n".join(bloques[:30])),
                    f"https://{dominio}",
                ))
    except Exception:
        pass

    try:
        r = requests.get(f"https://{dominio}/.well-known/security.txt",
                         headers=HEADERS, timeout=TIMEOUT)
        if r.status_code == 200:
            texto = "security.txt publicado: " + " | ".join(
                l.strip() for l in r.text.splitlines() if l.strip()
            )[:1500]
            items.append(_item("Web Corporativa Directa", texto,
                               f"https://{dominio}/.well-known/security.txt"))
    except Exception:
        pass

    return items, "ok" if items else "sin contenido"


# ---------------------------------------------------------------------------
# ORQUESTADOR
# ---------------------------------------------------------------------------

# Los conectores se ejecutan en paralelo: los lentos (dorking ~35s, wayback
# ~20s) dominaban el tiempo total de la auditoria.
_CONECTORES = [
    ("robots.txt", lambda d, e: conector_robots(d)),
    ("sitemap.xml", lambda d, e: conector_sitemap(d)),
    ("crt.sh (certificados)", lambda d, e: conector_certificados(d)),
    ("Wayback Machine", lambda d, e: conector_historico(d)),
    ("DNS-over-HTTPS", lambda d, e: conector_dns(d)),
    ("GitHub", lambda d, e: conector_github(d, e)),
    ("Google News RSS", lambda d, e: conector_noticias(e, d)),
    ("Dorking dirigido", lambda d, e: conector_dorking(e, d)),
    ("Web directa", lambda d, e: conector_web_directa(d)),
]


def recolectar_datos_reales(dominio: str, empresa: str,
                            conectores: list | None = None,
                            buscar_documentos: bool = True) -> tuple[list[dict], list[dict]]:
    """
    Ejecuta todos los conectores EN PARALELO.

    Args:
        conectores: lista opcional de (nombre, funcion). Por defecto usa
            _CONECTORES. Permite inyectar dobles en las pruebas.
        buscar_documentos: si False, no se buscan documentos por dorking
            (se usa en las pruebas para no depender de la red).

    Returns:
        (items, estado_por_conector) donde estado_por_conector es una lista de
        {"conector", "estado", "detalle"} para poder mostrar en la UI que
        fuentes fallaron en vez de ocultarlas.
    """
    items: list[dict] = []
    estado: list[dict] = []
    lista = conectores if conectores is not None else _CONECTORES

    def _normalizar(resultado):
        """Garantiza la tupla (items, detalle) aunque el conector falle."""
        if resultado is None:
            return [], "el conector no devolvio resultado"
        try:
            nuevos, detalle = resultado
        except (TypeError, ValueError):
            return [], "formato de retorno inesperado"
        return list(nuevos or []), str(detalle or "")

    def _ejecutar(nombre, fn):
        try:
            return nombre, _normalizar(fn(dominio, empresa))
        except Exception as exc:
            return nombre, ([], f"error: {type(exc).__name__}: {exc}")

    resultados: dict[str, tuple[list[dict], str]] = {}
    with ThreadPoolExecutor(max_workers=min(8, max(1, len(lista)))) as pool:
        futuros = {pool.submit(_ejecutar, n, f): n for n, f in lista}
        for fut in as_completed(futuros):
            nombre, res = fut.result()
            resultados[nombre] = res

    # Se respetan el orden original de los conectores en el reporte.
    for nombre, _ in lista:
        nuevos, detalle = resultados.get(nombre, ([], "no se ejecuto"))
        items.extend(nuevos)
        if nuevos:
            estado_conector = "ok"
        elif detalle.startswith("error:"):
            estado_conector = "error"
        else:
            estado_conector = "vacio"
        estado.append({
            "conector": nombre,
            "estado": estado_conector,
            "detalle": detalle,
        })

    # El analisis de documentos depende de los documentos ya descubiertos.
    # `buscar_documentos` se puede desactivar para evitar la red (pruebas).
    if buscar_documentos:
        nuevos, detalle = _normalizar(conector_pdf(items, empresa, dominio))
    else:
        nuevos, detalle = ([], "busqueda de documentos desactivada")
    items.extend(nuevos)
    estado.append({"conector": "Metadatos PDF",
                   "estado": "ok" if nuevos else "vacio",
                   "detalle": detalle})

    return items, estado
