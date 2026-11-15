"""
Nucleo de analisis del Indice de Vulnerabilidad a Pretextos (PVI).
Version unificada: Motor Auditor PVI + Capacidades de Social Eye (Secret Scanning,
Kit de 5 Piezas de Pretexto, Enmascaramiento Ley 25.326 y Recalculo Dinamico).

Modulo sin dependencias de Streamlit para poder testearse de forma aislada.
"""

from __future__ import annotations

import math
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any, Iterable, Sequence


# ---------------------------------------------------------------------------
# 1. NORMALIZACION DE TEXTO Y PROTECCION DE DATOS (LEY 25.326)
# ---------------------------------------------------------------------------

# Ruido de boilerplate comun en HTML (nav, cookies, traducciones, legal).
_BOILERPLATE_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in [
        r"aceptar\s+(todas\s+las\s+)?cookies",
        r"pol[ií]tica\s+(de\s+)?(privacidad|cookies)",
        r"traducido\s+por\s+google",
        r"todos\s+los\s+derechos\s+reservados",
        r"navegador\s+(no\s+)?soportado",
        r"habilite\s+javascript",
        r"saltar\s+al\s+contenido",
        r"recibir\s+(el\s+|nuestro\s+)?bolet[ií]n",
        r"suscr[ií]b(ase|ete|irse)\s+(a|al|para)",
        r"registrarme\s+con\s+mi\s+direcci[oó]n\s+de\s+correo",
        r"newsletter",
        r"^\s*(inicio|sitemap|contacto|acerca\s+de|privacidad)\s*$",
    ]
]

_EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
_URL_RE = re.compile(r"https?://[^\s<>\"')\]]+")
_PATH_RE = re.compile(r"(?<![\w])((?:/[\w.\-]+){1,6}/?)")
_CAMEL_RE = re.compile(r"[A-Z][a-z]+(?:[A-Z][a-z]+)+")

# --- Deteccion de secretos filtrados (integrado desde Social Eye) ---
_SECRETOS_PATTERNS = [
    ("webhook de Slack", re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/_+-]+")),
    ("token de Slack", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}")),
    ("clave de acceso AWS", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("clave de Google API", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("token de GitHub", re.compile(r"\bghp_[A-Za-z0-9]{36}\b")),
    ("clave privada", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("credencial expuesta", re.compile(
        r"(?i)(?:api[_-]?key|secret|password|passwd|token)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{12,}"
    )),
]

# --- Las 5 piezas del "Kit del Pretexto" (integrado desde Social Eye) ---
PIEZAS_KIT: dict[str, str] = {
    "identidad": "Entidad suplantable (proveedor, consultora, soporte, área interna, directivo)",
    "contexto": "Motivo o excusa verosímil (proyecto, migración, auditoría, licitación, evento)",
    "canal": "A quién contactar y por qué vía (correos, teléfonos, nombres con rol o autor)",
    "jerga": "Tecnología, sistemas o rutas internas que dan credibilidad al pretexto",
    "urgencia": "Palancas de presión o autoridad (cierre de trimestre, plazos, secretos críticos)",
}

_TERMINOS_URGENCIA = {
    "urgente", "inmediato", "cuanto antes", "deadline", "vencimiento",
    "cierre de trimestre", "cierre de mes", "fin de ano", "obligatorio",
    "critico", "antes del", "plazo", "auditoria", "licitacion",
}


def detectar_secretos(texto: str) -> list[str]:
    """Detecta credenciales, webhooks o tokens filtrados en el texto original."""
    if not texto:
        return []
    hallados: list[str] = []
    for nombre, pat in _SECRETOS_PATTERNS:
        if pat.search(texto) and nombre not in hallados:
            hallados.append(nombre)
    return hallados


def enmascarar_texto_sensible(texto: str) -> str:
    """
    Enmascara emails y posibles nombres de usuario (Ley 25.326 de Proteccion
    de Datos Personales) cuando el analista activa el modo de privacidad.
    """
    if not texto:
        return ""
    # Enmascara la parte local de los correos: mgarcia@empresa.com -> m***@empresa.com
    texto_masc = re.sub(
        r"\b([a-zA-Z0-9])[a-zA-Z0-9._%+-]*(@[\w-]+\.[\w.-]+)",
        r"\1***\2",
        texto,
    )
    # Enmascara handles tipo @usuario
    texto_masc = re.sub(r"(?<!\w)@[a-zA-Z0-9_]{3,}", "@***", texto_masc)
    # Enmascara "Autor declarado en metadatos: Nombre"
    texto_masc = re.sub(
        r"(Autor declarado en metadatos:\s*)([A-Za-zÁÉÍÓÚáéíóúÑñ])[^\n.]+",
        r"\1\2*** (protegido Ley 25.326)",
        texto_masc,
    )
    return texto_masc


def enmascarar_actor(actor: str) -> str:
    """Enmascara el nombre propio de una persona (PER) conservando las organizaciones (ORG)."""
    if "(PER)" in actor or "(PERSON)" in actor:
        nombre = actor.split(" (")[0].strip()
        etiqueta = actor[len(nombre):]
        partes = nombre.split()
        masc = " ".join(p[0] + "***" for p in partes if p)
        return f"{masc}{etiqueta}"
    if "@" in actor:
        return re.sub(r"^([a-zA-Z0-9])[a-zA-Z0-9._%+-]*@", r"\1***@", actor)
    return actor


def mapear_piezas_kit(categorias: Iterable[str],
                      terminos: Iterable[str],
                      actores: Iterable[str],
                      secretos: Iterable[str],
                      texto_norm: str = "") -> list[str]:
    """
    Traduce las categorias y senales de un hallazgo a las 5 piezas del Kit
    de Pretexto de Social Eye (identidad, contexto, canal, jerga, urgencia).
    """
    cats = set(categorias)
    terms = {normalizar(t) for t in terminos}
    acts = list(actores)
    secs = list(secretos)
    piezas: set[str] = set()

    if "ROL_ALTO" in cats or acts or any(t in terms for t in ("proveedor", "consultora", "soporte", "rrhh")):
        piezas.add("identidad")
    if "PROCESO_ALTO" in cats:
        piezas.add("contexto")
    if "CONTACTO_DIRECTO" in cats or "METADATOS_DOC" in cats or any("(PER" in a or "@" in a for a in acts):
        piezas.add("canal")
    if "SOFTWARE" in cats or "CRITICO" in cats or secs:
        piezas.add("jerga")
    if secs or any(u in texto_norm for u in _TERMINOS_URGENCIA) or ("ROL_ALTO" in cats and "PROCESO_ALTO" in cats):
        piezas.add("urgencia")

    return [p for p in PIEZAS_KIT if p in piezas]


def normalizar(texto: str) -> str:
    """Minusculas, sin acentos y con espacios colapsados."""
    if not texto:
        return ""
    texto = unicodedata.normalize("NFKD", str(texto))
    texto = "".join(c for c in texto if not unicodedata.combining(c))
    texto = texto.casefold()
    return re.sub(r"\s+", " ", texto).strip()


def quitar_boilerplate(texto: str) -> str:
    """Elimina frases de navegacion, cookies y avisos legales."""
    if not texto:
        return ""
    lineas = []
    for linea in str(texto).splitlines():
        limpia = linea.strip()
        if not limpia:
            continue
        if any(p.search(limpia) for p in _BOILERPLATE_PATTERNS):
            continue
        lineas.append(limpia)
    return "\n".join(lineas)


def limpiar_texto_analizable(texto: str) -> str:
    """
    Pipeline completo de limpieza previo al NLP.
    Se conservan las RUTAS de las URLs (el path), porque en exposures
    tecnicas la ruta es la evidencia ("/wp-admin/", "/backup.sql"). Solo se
    elimina el esquema y el host, que no aportan senal de riesgo.
    """
    texto = quitar_boilerplate(texto)
    texto = re.sub(r"https?://[^\s/]+", " ", texto)
    texto = re.sub(r"[ \t]+", " ", texto)
    texto = re.sub(r"\n{2,}", "\n", texto)
    return texto.strip()


def _clave_dedup(texto: str) -> str:
    """Clave canonica para detectar textos duplicados o casi identicos."""
    base = normalizar(texto)
    base = re.sub(r"[^\w\s]", " ", base)
    base = re.sub(r"\s+", " ", base).strip()
    return base


def similitud_jaccard(a: str, b: str) -> float:
    """Similitud de conjuntos de tokens (para dedup tolerante a variaciones)."""
    ta = set(_clave_dedup(a).split())
    tb = set(_clave_dedup(b).split())
    if not ta or not tb:
        return 0.0
    return len(ta & tb) / len(ta | tb)


_STOP_SIMILITUD = {
    "el", "la", "los", "las", "un", "una", "unos", "unas", "de", "del", "al",
    "y", "o", "u", "e", "en", "con", "por", "para", "que", "se", "su", "sus",
    "es", "son", "fue", "fueron", "esta", "este", "esto", "como", "mas", "muy",
    "a", "the", "of", "and", "to", "in", "for", "on", "is", "are", "was",
    "an", "at", "be", "by", "or", "we", "our", "us", "that", "this",
}


def _tokens_contenido(texto: str) -> set[str]:
    """Tokens con carga semantica (sin stopwords) para comparar temas."""
    return {
        t for t in re.findall(r"[\w]+", normalizar(texto))
        if len(t) > 2 and t not in _STOP_SIMILITUD
    }


def _entidades_clave(texto: str) -> set[str]:
    """Tokens especialmente discriminantes: nombres propios, proveedores, roles."""
    tokens = re.findall(r"[\w]+", normalizar(texto))
    genericas = {
        "proyecto", "project", "equipo", "team", "company", "empresa", "announcement",
        "anuncia", "comenzo", "empieza", "empezar", "inicio", "nuevo", "nueva",
        "feliz", "celebrar", "celebramos", "comenzamos", "arrancamos", "lanza",
        "presenta", "presentamos", "blog", "news", "noticias", "home", "www",
        "http", "https", "linkedin", "posts", "share", "artículo", "articulo",
    }
    return {
        t for t in tokens
        if len(t) > 3 and t not in _STOP_SIMILITUD and t not in genericas
    }


_DISTINTORES = {
    "principal", "secundario", "terciario", "norte", "sur", "este", "oeste",
    "nuevo", "nueva", "viejo", "anterior", "alternativo", "respaldo", "backup",
    "primario", "central", "externo", "interno", "publico", "privado",
    "prod", "staging", "desarrollo", "produccion",
    "alpha", "beta", "gamma", "uno", "dos", "tres",
}


def _hay_distintores_en_conflicto(a: str, b: str) -> bool:
    """True si los dos textos califican la misma entidad con DISTINTORES distintos."""
    da = set(re.findall(r"[\w]+", normalizar(a))) & _DISTINTORES
    db = set(re.findall(r"[\w]+", normalizar(b))) & _DISTINTORES
    if not da or not db:
        return False
    return da.isdisjoint(db)


def similitud_tematica(a: str, b: str) -> float:
    """Similitud tematica entre dos fragmentos (0..1)."""
    ta = _tokens_contenido(a)
    tb = _tokens_contenido(b)
    if not ta or not tb:
        return 0.0
    inter = ta & tb
    if not inter:
        return 0.0
    jaccard = len(inter) / len(ta | tb)
    containment = len(inter) / min(len(ta), len(tb))

    ea = _entidades_clave(a)
    eb = _entidades_clave(b)
    if ea and eb:
        e_inter = ea & eb
        sim_ent = len(e_inter) / min(len(ea), len(eb))
        if _hay_distintores_en_conflicto(a, b):
            sim_ent *= 0.25
    else:
        sim_ent = 0.0

    return round(min(1.0, 0.3 * jaccard + 0.3 * containment + 0.4 * sim_ent), 4)


def es_duplicado_tematico(a: str, b: str, umbral: float = 0.55) -> bool:
    """True si dos fragmentos hablan del mismo tema (misma publicacion)."""
    return similitud_tematica(a, b) >= umbral


# ---------------------------------------------------------------------------
# 2. RELEVANCIA: UN RESULTADO SOLO CUENTA SI HABLA DEL OBJETIVO
# ---------------------------------------------------------------------------

_STOP_EMPRESA = {
    "sa", "sas", "srl", "sra", "spa", "ltda", "limitada", "grupo", "empresa",
    "corporacion", "corporation", "corp", "company", "co", "inc", "llc",
    "the", "and", "de", "del", "la", "el", "los", "las", "y", "en", "para",
    "servicios", "sistemas", "tecnologia", "tecnologias", "soluciones",
    "consultoria", "holding", "society", "translations",
}


def tokens_identificadores(empresa: str) -> list[str]:
    """Tokens que identifican a la organizacion (descartan ruido legal)."""
    tokens = re.findall(r"[\w]+", normalizar(empresa))
    return [t for t in tokens if t not in _STOP_EMPRESA and len(t) > 2]


def _variantes_empresa(empresa: str) -> list[str]:
    """Variantes textuales aceptables para el nombre de la empresa."""
    variantes = {normalizar(empresa)}
    base = normalizar(empresa)
    for sufijo in (" s a", " s r l", " s a s", " ltda", " spa"):
        if base.endswith(sufijo):
            variantes.add(base[: -len(sufijo)].strip())
    partes = base.split()
    if len(partes) > 1:
        variantes.add(" ".join(partes[:-1]))
    return [v for v in variantes if len(v) > 2]


def evaluar_relevancia(texto: str, empresa: str, dominio: str,
                       url: str = "") -> tuple[bool, float, str]:
    """Determina si un fragmento es atribuible a la organizacion auditada."""
    if not texto or not texto.strip():
        return False, 0.0, "texto_vacio"

    hay_domino = bool(dominio) and dominio.lower() in texto.lower()
    hay_url_domino = bool(dominio) and dominio.lower() in (url or "").lower()

    variantes = _variantes_empresa(empresa)
    texto_norm = normalizar(texto)
    url_norm = normalizar(url)

    coincide_empresa = any(v in texto_norm or v in url_norm for v in variantes)

    tokens = tokens_identificadores(empresa)
    tokens_texto = set(re.findall(r"[\w]+", texto_norm))
    tokens_url = set(re.findall(r"[\w]+", url_norm))
    coincide_parcial = bool(tokens) and bool(
        (tokens_texto | tokens_url) & set(tokens)
    )

    if hay_domino or hay_url_domino:
        return True, 0.95, "menciona_dominio"
    if coincide_empresa:
        return True, 0.9, "menciona_empresa"
    if coincide_parcial:
        return True, 0.6, "coincidencia_parcial"
    return False, 0.0, "sin_mencion_del_objetivo"


def extraer_identificadores_directos(texto: str, dominio: str) -> list[str]:
    """Emails/URLs del dominio objetivo: senal de exposicion directa."""
    if not dominio:
        return []
    encontrados = []
    for m in _EMAIL_RE.finditer(texto or ""):
        if dominio.lower() in m.group(0).lower():
            encontrados.append(m.group(0))
    for m in _URL_RE.finditer(texto or ""):
        if dominio.lower() in m.group(0).lower():
            encontrados.append(m.group(0))
    return list(dict.fromkeys(encontrados))


_MAPA_INFRA_SOCIAL = {
    "outlook.com": "Microsoft 365 / Outlook",
    "protection.outlook.com": "Microsoft 365 / Outlook",
    "_spf.google.com": "Google Workspace",
    "google-site-verification": "Google Workspace",
    "amazonses.com": "Amazon SES / AWS",
    "zendesk.com": "Zendesk",
    "jira": "Jira",
    "confluence": "Confluence",
    "gitlab": "GitLab",
    "vpn": "VPN Corporativa",
    "citrix": "Citrix",
    "fortinet": "Fortinet",
    "wp-admin": "WordPress",
}


def extraer_stack_tecnico_verificado(documentos: list[dict[str, Any]]) -> set[str]:
    """Extrae herramientas confirmadas por fuentes tecnicas (DNS, Certs, Robots) para enriquecer pretextos."""
    stack: set[str] = set()
    fuentes_tecnicas = {
        "DNS / Registros TXT",
        "Subdominios (Certificados)",
        "Robots.txt / Sitemaps",
        "Historico Web (Wayback)",
    }
    for doc in documentos:
        if doc.get("fuente") in fuentes_tecnicas:
            texto = (doc.get("texto", "") or "").lower()
            for marcador, herramienta in _MAPA_INFRA_SOCIAL.items():
                if marcador in texto:
                    stack.add(herramienta)
    return stack


def calcular_anclaje_tecnico(documentos: list[dict[str, Any]]) -> dict[str, float]:
    """
    Calcula el aporte de las fuentes tecnicas (Robots, Subdominios, Wayback, DNS)
    como 'Anclaje de Credibilidad Tecnica' para un pretexto social.
    """
    aportes: dict[str, float] = {}
    marcadores_criticos = {
        "vpn", "admin", "wp-admin", "staging", "intranet", "backup", "config",
        "jira", "gitlab", "jenkins", "dev", "test", "internal", "portal",
        "nomina", "sql", "xlsx", "spf", "google-site-verification", "outlook",
    }
    topes_por_fuente = {
        "Robots.txt / Sitemaps": 4.0,
        "Subdominios (Certificados)": 4.5,
        "Historico Web (Wayback)": 4.0,
        "DNS / Registros TXT": 2.0,
    }
    for doc in documentos:
        fuente = doc.get("fuente", "")
        if fuente not in topes_por_fuente:
            continue
        texto = normalizar(doc.get("texto", ""))
        hits = sum(1 for m in marcadores_criticos if m in texto)
        if hits > 0:
            tope = topes_por_fuente[fuente]
            pts = min(tope, tope * (1.0 - math.exp(-hits / 2.5)))
            aportes[fuente] = round(max(aportes.get(fuente, 0.0), pts), 2)
    return aportes


# ---------------------------------------------------------------------------
# 3. TAXONOMIA DE SENALES
# ---------------------------------------------------------------------------

CATEGORIAS: dict[str, dict[str, Any]] = {
    "CRITICO": {
        "peso": 1.00,
        "descripcion": "Credenciales, rutas administrativas o endpoints sensibles.",
        "social": False,
        "frases": [
            "wp-admin", "panel de administracion", "administrador", "credenciales",
            "contrasena", "clave de api", "api key", "access token", "refresh token",
            "archivo de configuracion", "configuracion", "copia de seguridad",
            "panel de control", "intranet", "vpn", "ssh", "servidor interno",
            "base de datos", "directorio compartido", "gestion documental",
        ],
        "unicos": ["admin", "backup", "staging", "dev", "vpn", "intranet",
                   "password", "contrasena", "token", "credenciales", "secret",
                   "firewall", "repository", "repo"],
        "contexto": ["ruta", "path", "directorio", "servidor", "endpoint", "url",
                     "http", "https", "host", "dominio", "archivo", "config",
                     "configuracion", "credencial", "usuario", "login", "acceso",
                     "panel", "correo", "email", "contrasena", "token", "api"],
        "requiere_contexto": True,
    },
    "PROCESO_ALTO": {
        "peso": 0.65,
        "descripcion": "Procesos de negocio sensibles que habilitan pretextos.",
        "social": True,
        "frases": [
            "migracion de servidores", "migracion de datos", "auditoria externa",
            "auditoria de sistemas", "facturacion electronica", "licitacion publica",
            "licitacion de obras", "contratacion de proveedores", "despliegue de sistemas",
            "plan de continuidad", "recuperacion ante desastres", "gestion de tesoreria",
            "conciliacion bancaria", "nominas depersonal", "evaluacion de desempenho",
            "onboarding de empleados", "offboarding", "gestion de proveedores",
            "transformacion digital", "cloud migration", "talent acquisition",
        ],
        "unicos": ["migracion", "auditoria", "facturacion", "licitacion",
                   "mantenimiento", "proveedor", "contratacion", "despliegue",
                   "actualizacion", "tesoreria", "nomina", "continuidad",
                   "onboarding", "reclutamiento", "seleccion", "implementacion",
                   "arquitectura", " Operaciones", "operations", "procurement",
                   "billing", "payroll", "deployment", "migration"],
        "contexto": [],
        "requiere_contexto": False,
    },
    "ROL_ALTO": {
        "peso": 0.60,
        "descripcion": "Roles y departamentos con capacidad de decision o firma.",
        "social": True,
        "frases": [
            "recursos humanos", "rrhh", "finanzas", "tesoreria", "sistema de compras",
            "departamento de compras", "mesa de ayuda", "servicio de soporte",
            "centro de servicios", "infraestructura", "seguridad de la informacion",
            "direccion general", "direccion de finanzas", "comite de direccion",
            "responsable de seguridad", "oficial de cumplimiento", "auditor interno",
            "talent acquisition", "human resources", "tech lead", "team lead",
            "project manager", "product owner", "scrum master", "it manager",
            "head of", "vp of", "vice president", "managing director",
            "account manager", "business development", "customer success",
            "software engineer", "devops engineer", "cloud architect",
            "security analyst", "information security", "people partner",
        ],
        "unicos": ["soporte", "helpdesk", "sistemas", "director", "gerente",
                   "ceo", "cfo", "cto", "coo", "ciso", "responsable", "coordinador",
                   "jefe", "analista", "contador", "abogado", "auditor",
                   "recruiter", "reclutador", "reclutadora", "manager", "lead",
                   "lider", "architect", "arquitecto", "engineer", "ingeniero",
                   "developer", "desarrollador", "consultant", "consultor",
                   "specialist", "especialista", "partner", "president", "vp"],
        "contexto": [],
        "requiere_contexto": False,
    },
    "SOFTWARE": {
        "peso": 0.45,
        "descripcion": "Software corporativo y proveedores de infraestructura.",
        "social": True,
        "frases": [
            "office 365", "microsoft 365", "active directory", "exchange server",
            "sharepoint", "google workspace", "microsoft teams", "sap erp",
            "sap hana", "salesforce", "workday", "netsuite", "microsoft azure",
            "amazon web services", "vmware vsphere", "citrix", "okta",
            "crowdstrike", "fortinet fortigate", "mikrotik router",
        ],
        "unicos": ["sap", "aws", "salesforce", "jira", "confluence", "zendesk",
                   "okta", "workday", "netsuite", "odoo", "cisco", "fortinet",
                   "mikrotik", "exchange", "sharepoint", "azure", "grafana"],
        "contexto": [],
        "requiere_contexto": False,
    },
    "CONTACTO_DIRECTO": {
        "peso": 0.80,
        "descripcion": "Datos de contacto o credenciales de acceso del objetivo.",
        "social": True,
        "frases": ["correo electronico", "email de contacto", "linea directa",
                   "telefono de la central", "usuario contrasena"],
        "unicos": ["correo", "telefono", "celular", "whatsapp", "extension",
                   "usuario", "clave", "login"],
        "contexto": ["@", "correo", "email", "telefono", "contacto", "usuario",
                     "clave", "password", "login", "http", "www"],
        "requiere_contexto": True,
    },
    "METADATOS_DOC": {
        "peso": 0.55,
        "descripcion": "Autor o nombre de archivo de un documento publico.",
        "social": True,
        "frases": ["autor declarado en metadatos", "creado por", "elaborado por",
                   "formulario de proveedores", "lista de proveedores",
                   "directorio de personal", "planilla de nominas"],
        "unicos": ["autor", "autora", "metadatos", "editor", "redactor",
                   "creado", "elaborado", "revision", "aprobado"],
        "contexto": ["metadatos", "autor", "documento", "archivo", "pdf",
                     "formulario", "planilla", "hoja de calculo", "plantilla"],
        "requiere_contexto": True,
    },
}

MULTIPLICADORES = {nombre: cfg["peso"] for nombre, cfg in CATEGORIAS.items()}
ETIQUETAS_ACTOR = {"PER", "ORG", "PERSON"}

_PRODUCTORES_GENERICOS = {
    "adobe", "acrobat", "microsoft", "word", "excel", "powerpoint", "openoffice",
    "libreoffice", "pages", "pdftk", "itext", "wkhtmltopdf", "chromium",
    "google", "chrome", "canva", "scanner", "ocrmypdf", "tcpdf", "fpdf",
}


def frase_a_patrones(frases: Iterable[str]) -> list[dict[str, Any]]:
    """Convierte frases en patrones de EntityRuler token por token."""
    patrones = []
    for frase in frases:
        tokens = frase.lower().split()
        if not tokens:
            continue
        patrones.append({
            "label": "PVI",
            "pattern": [{"LOWER": t} for t in tokens],
        })
    return patrones


def construir_patrones_ruler() -> list[dict[str, Any]]:
    """Patrones del EntityRuler con soporte de frases y lemas (spaCy >= 3.3)."""
    patrones = []
    for categoria, cfg in CATEGORIAS.items():
        for frase in cfg["frases"]:
            tokens = frase.lower().split()
            if not tokens:
                continue
            patrones.append({
                "label": categoria,
                "pattern": [{"LOWER": t} for t in tokens],
            })
        for unico in cfg["unicos"]:
            patrones.append({
                "label": categoria,
                "pattern": [{"LEMMA": unico.lower()}],
            })
    return patrones


# ---------------------------------------------------------------------------
# 4. DETECCION DE SENALES POR CATEGORIA (con control de contexto)
# ---------------------------------------------------------------------------

def _contiene_frase(texto_norm: str, frase: str) -> bool:
    """Busca la frase respetando limites de palabra."""
    patron = r"(?<!\w)" + r"\s+".join(re.escape(t) for t in frase.split()) + r"(?!\w)"
    return re.search(patron, texto_norm) is not None


def tiene_contexto_tecnico(texto_norm: str, categoria: str) -> bool:
    """Verifica que el termino ambiguo aparezca junto a contexto de exposicion."""
    contexto = CATEGORIAS.get(categoria, {}).get("contexto", [])
    if not contexto:
        return True
    for token in contexto:
        if re.search(r"(?<!\w)" + re.escape(token) + r"(?!\w)", texto_norm):
            return True
    return False


def detectar_categorias(texto: str, contexto_tecnico: bool = False,
                        excluir: set[str] | None = None,
                        doc_nlp: Any = None,
                        dominio: str = "") -> dict[str, list[str]]:
    """Detecta que categorias de riesgo aparecen en un fragmento."""
    texto_norm = normalizar(texto)
    if not texto_norm:
        return {}

    excluidos = {normalizar(t) for t in (excluir or set())}
    detectadas: dict[str, list[str]] = {}

    if doc_nlp is not None:
        for ent in getattr(doc_nlp, "ents", []):
            cat = ent.label_
            if cat not in CATEGORIAS:
                continue
            ent_norm = normalizar(ent.text)
            if not ent_norm or ent_norm in excluidos or ent_norm not in texto_norm:
                continue
            requiere_ctx = CATEGORIAS[cat].get("requiere_contexto", False)
            es_frase = len(ent_norm.split()) > 1
            if requiere_ctx and not es_frase and not (contexto_tecnico or tiene_contexto_tecnico(texto_norm, cat)):
                continue
            detectadas.setdefault(cat, []).append(ent_norm)

    for categoria, cfg in CATEGORIAS.items():
        terminos: list[str] = list(detectadas.get(categoria, []))
        for frase in cfg["frases"]:
            if normalizar(frase) in excluidos:
                continue
            if _contiene_frase(texto_norm, frase):
                terminos.append(frase)

        requiere_ctx = cfg.get("requiere_contexto", False)
        if requiere_ctx and not (contexto_tecnico or tiene_contexto_tecnico(texto_norm, categoria)):
            unicos_validos = []
        else:
            unicos_validos = cfg["unicos"]

        for termino in unicos_validos:
            if normalizar(termino) in excluidos:
                continue
            patron_plural = r"(?<!\w)" + re.escape(termino) + r"(?:es|s)?(?!\w)"
            if re.search(patron_plural, texto_norm):
                terminos.append(termino)

        if categoria == "CONTACTO_DIRECTO":
            emails_en_texto = _EMAIL_RE.findall(texto or "")
            if emails_en_texto and dominio:
                dom_low = dominio.lower()
                tiene_email_valido = any(
                    e.lower().endswith(("@" + dom_low, "." + dom_low))
                    for e in emails_en_texto
                )
            else:
                tiene_email_valido = bool(emails_en_texto)
            tiene_telefono = bool(re.search(r"\b\+?\d[\d\s\-]{6,}\d\b", texto))
            if not (tiene_email_valido or tiene_telefono):
                terminos = []

        if terminos:
            detectadas[categoria] = sorted(set(terminos))

    return detectadas


def es_productor_generico(texto: str) -> bool:
    """True si el texto solo describe un generador de PDF sin valor de riesgo."""
    tokens = [t for t in re.findall(r"[\w]+", normalizar(texto))
              if not t.isdigit()]
    if not tokens:
        return True
    return all(t in _PRODUCTORES_GENERICOS for t in tokens)


# ---------------------------------------------------------------------------
# 3b. FILTRO DE RUIDO Y DE ENUMERACION TECNICA PURA
# ---------------------------------------------------------------------------

_MARCAS_GENERICAS = {
    "microsoft", "word", "excel", "powerpoint", "outlook", "teams", "onenote",
    "adobe", "acrobat", "photoshop", "illustrator", "chrome", "chromium",
    "firefox", "safari", "edge", "opera", "brave", "google", "chromeos",
    "android", "ios", "iphone", "windows", "linux", "macos", "mac", "ubuntu",
    "office", "openoffice", "libreoffice", "pages", "numbers", "keynote",
    "zoom", "slack", "notion", "trello", "canva", "scanner", "printer",
    "version", "built", "with", "using", "copyright", "todos", "derechos",
    "reservados", "privacidad", "cookies", "aceptar", "navegador",
    "javascript", "soportado", "traducido", "google", "translate",
}

_TECNICO_PURO = {
    "subdominio", "subdominios", "registro", "registros", "txt", "mx", "cname",
    "ns", "soa", "dns", "resuelven", "apunta", "apuntan", "servidor", "servidores",
    "certificado", "certificados", "transparencia", "emision", "emisores",
    "ruta", "rutas", "path", "directorio", "archivos", "extensiones", "url",
    "urls", "indice", "http", "https", "host", "dominio", "endpoints",
}

_ACTORES_GENERICOS = {
    "el equipo", "la empresa", "la organizacion", "el equipo de trabajo",
    "nuestro equipo", "el proyecto", "la proyecto", "el cliente", "el sector",
    "el mercado", "el mundo", "la industria", "todos",
    "nosotros", "ellos", "ustedes", "nuestra empresa",
    "la sociedad", "el gobierno",
    "la institucion", "el sistema", "la plataforma", "el portal", "la aplicacion",
    "el servicio", "nuestro proyecto", "el area", "el equipo tecnico",
    "texto", "documento", "contenido", "pagina", "archivo", "noticia", "blog",
    "articulo", "post", "mensaje", "titulo", "encabezado", "resumen",
}

_MARCAS_CODIGO = {
    "define", "function", "return", "var ", "let ", "const ", "class ",
    "import ", "from ", "print", "echo", "console.log", "printf", "if (",
    "else", "foreach", "while", "public ", "private ", "protected ",
    "static ", "void ", "int ", "string ", "bool ", "null", "true", "false",
    "undefined", "self", "this.", "=>", "::", "</", "/>", "<!--", "-->",
    "self.", "null;", "endif", "endforeach", "namespace", "use ", "new ",
}

_AUTORES_GENERICOS = {
    "microsoft office user", "user", "unknown", "desconocido", "admin",
    "administrator", "owner", "creator", "author", "default", "none",
    "microsoft", "windows user", "microsoft office", "oem", "test",
    "null", "system", "usuario", "root", "pdfsam", "pdf creator",
    "pdfmaker", "libreoffice", "openoffice", "docprops", "microsoft word",
    "microsoft excel", "microsoft publisher", "microsoft office 365",
}


def autor_es_generico(autor: str) -> bool:
    """True si el autor de los metadatos no identifica a una persona real."""
    a = normalizar(autor).strip(" .,")
    if not a:
        return True
    if a in _AUTORES_GENERICOS:
        return True
    if a.endswith(" user") or a.endswith(" usuario"):
        return True
    if "office" in a or a.startswith("pdf"):
        return True
    if len(a) < 3:
        return True
    return False


_SCHEMATICOS = {
    "login", "logout", "signup", "signin", "register", "home", "menu",
    "contact", "about", "search", "more", "next", "previous", "back",
    "cookie", "cookies", "privacy", "terms", "help", "support", "faq",
    "sitemap", "troubleshoot", "issues", "issue", "settings", "profile",
    "account", "dashboard", "overview", "read more", "learn more",
}


def _es_nombre_propio(texto: str, token: str) -> bool:
    for m in re.finditer(re.escape(token), texto, re.IGNORECASE):
        inicio = m.start()
        if inicio == 0:
            continue
        anterior = texto[inicio - 1]
        if not (anterior.isalpha() or anterior.isdigit()):
            return texto[m.start()].isupper()
    return False


def es_fragmento_esquematico(texto: str) -> bool:
    """True si el fragmento es una etiqueta de navegacion, no una frase con contenido."""
    norm = normalizar(texto)
    if not norm:
        return True
    tokens = re.findall(r"[\w]+", norm)
    if not tokens:
        return True
    verbos_contenido = {
        "comenzo", "empezamos", "inicio", "anuncio", "movemos", "contratamos",
        "publico", "participa", "junto", "equipo", "proyecto", "proveedor",
        "cliente", "auditoria", "migracion", "despliegue", "contratacion",
        "facturacion", "nominas", "nomina", "continuidad", "evaluacion",
        "onboarding", "capacitacion", "reunion", "entrega", "lanzamos",
        "celebramos", "feliz", "nuevo", "nueva", "acuerdo", "alianza", "compra",
        "proveedores", "consultora", "consultoria", "trabajo",
        "socio", "director", "gerente", "responsable", "coordinador",
        "jefe", "analista", "soporte", "finanzas", "rrhh", "recursos",
        "amazon", "google", "microsoft", "sap", "aws", "oracle", "adobe",
        "estrenamos", "incorporamos", "asociamos", "respaldamos", "garantizamos",
    }
    if any(t in verbos_contenido for t in tokens):
        return False
    if all(t in _SCHEMATICOS for t in tokens):
        return True
    if len(tokens) <= 6 and all(len(t) <= 4 for t in tokens):
        return True
    sustantivos = [t for t in tokens if t not in _SCHEMATICOS and len(t) > 4]
    if not sustantivos:
        return True
    if len(tokens) <= 4:
        if all(t in _SCHEMATICOS or _es_nombre_propio(texto, t) for t in tokens):
            return True
    return False


def es_codigo_fuente(texto: str) -> bool:
    """True si el fragmento es CODIGO FUENTE pegado, no un relato en lenguaje natural."""
    norm = normalizar(texto)
    if not norm:
        return False
    marcas = sum(1 for m in _MARCAS_CODIGO if m in norm)
    if marcas >= 2:
        tokens = re.findall(r"[\w]+", norm)
        if tokens:
            proporcion = marcas / len(tokens)
            if proporcion >= 0.30:
                return True
            if len(norm) < 400 and proporcion >= 0.15:
                return True
    if len(norm) < 400:
        if re.search(r"[;{}]\s*\S", norm) and re.search(r"[(){}]\s*\w+\s*[=,)]", norm):
            if len(re.findall(r"[;(){}]", norm)) >= 4:
                return True
        if re.search(r"\w+\s*\(\s*['\"]?\w+['\"]?\s*,", norm):
            if len(re.findall(r"[;()]", norm)) >= 4:
                return True
    return False


def es_ruido_generico(texto: str) -> bool:
    """True si el fragmento esta compuesto solo de marcas/productoras sin valor."""
    tokens = [t for t in re.findall(r"[\w]+", normalizar(texto))
              if not t.isdigit() and len(t) > 1]
    if not tokens:
        return True
    relevantes = [t for t in tokens if t not in _MARCAS_GENERICAS]
    if not relevantes:
        return True
    if len(tokens) >= 4 and (len(relevantes) / len(tokens)) < 0.4:
        return True
    return False


def es_enumeracion_tecnica_pura(texto: str) -> bool:
    """True si el fragmento es una lista de recursos tecnicos, no un relato social."""
    norm = normalizar(texto)
    tokens = [t for t in re.findall(r"[\w]+", norm) if len(t) > 1]
    if not tokens:
        return False
    if re.match(r"^(disallow|allow|sitemap)\s*:", norm):
        return True
    if re.search(r"\b(disallow|allow)\s*:\s*/", norm):
        return True
    if re.search(r"(\b(txt|mx|cname|ns|soa|a|aaaa)\b\s*\)?\s*:|^servidor\s+de\s+correo)", norm):
        return True
    n_tec = sum(1 for t in tokens if t in _TECNICO_PURO)
    ratio = n_tec / len(tokens)
    if ratio < 0.20:
        return False
    n_hosts = len(re.findall(r"[\w-]+\.[a-z]{2,}", norm))
    n_rutas = len(re.findall(r"/[\w.-]+", norm))
    if n_hosts >= 2 or n_rutas >= 2:
        return True
    if n_rutas >= 1 and ratio >= 0.30:
        return True
    return ratio >= 0.4


def _coincide_con_nombre_documento(actor: str, texto: str) -> bool:
    nombre = normalizar(actor.split(" (")[0])
    if not nombre:
        return False
    m = re.search(r"Documento publico:\s*([^.\n]+)", texto)
    if not m:
        return False
    nombre_doc = normalizar(m.group(1))
    if not nombre_doc:
        return False
    if nombre == nombre_doc:
        return True
    tokens_doc = set(nombre_doc.split())
    tokens_actor = set(nombre.split())
    if tokens_actor and tokens_actor.issubset(tokens_doc):
        return True
    return False


def actor_es_generico(actor: str) -> bool:
    """True si el "actor" detectado es un sustantivo generico, no una entidad."""
    texto = normalizar(actor.split(" (")[0])
    if texto in _ACTORES_GENERICOS:
        return True
    if len(texto.split()) == 1 and texto in {"equipo", "proyecto", "empresa",
                                            "organizacion", "cliente", "area"}:
        return True
    return False


def tiene_senal_social(categorias: dict[str, list[str]]) -> bool:
    """True si alguna categoria detectada describe CONTEXTO SOCIAL."""
    return any(CATEGORIAS.get(c, {}).get("social", False) for c in categorias)


# ---------------------------------------------------------------------------
# 5. MOTOR NLP (spaCy + EntityRuler corregido)
# ---------------------------------------------------------------------------

_MODELO_NLP = None


def obtener_nlp():
    """Carga y cachea el pipeline de espanol con el EntityRuler corregido."""
    global _MODELO_NLP
    if _MODELO_NLP is not None:
        return _MODELO_NLP
    import spacy
    nlp = spacy.load("es_core_news_md")
    if "pvi_ruler" not in nlp.pipe_names:
        ruler = nlp.add_pipe("entity_ruler", name="pvi_ruler", before="ner")
        ruler.add_patterns(construir_patrones_ruler())
    _MODELO_NLP = nlp
    return nlp


# ---------------------------------------------------------------------------
# 6. FORMULA PVI Y ESTRUCTURAS DE DATOS
# ---------------------------------------------------------------------------

PESOS_FUENTE: dict[str, dict[str, Any]] = {
    "Metadatos PDF":               {"peso": 6.5, "confianza": 0.85, "categoria": "Documentos"},
    "Robots.txt / Sitemaps":      {"peso": 7.0, "confianza": 0.95, "categoria": "Tecnico"},
    "Subdominios (Certificados)": {"peso": 6.5, "confianza": 0.90, "categoria": "Tecnico"},
    "Historico Web (Wayback)":   {"peso": 6.0, "confianza": 0.85, "categoria": "Tecnico"},
    "DNS / Registros TXT":        {"peso": 6.0, "confianza": 0.85, "categoria": "Tecnico"},
    "GitHub / Codigo":            {"peso": 6.0, "confianza": 0.85, "categoria": "Codigo"},
    "OSINT Redes / Dorking":      {"peso": 5.8, "confianza": 0.80, "categoria": "OSINT"},
    "Noticias / Blog Corporativo":{"peso": 4.2, "confianza": 0.80, "categoria": "Medios"},
    "Web Corporativa Directa":    {"peso": 3.5, "confianza": 0.90, "categoria": "Web"},
}

PESO_FUENTE_POR_DEFECTO = {"peso": 3.0, "confianza": 0.60, "categoria": "Desconocida"}

K_SATURACION = 26.0
BONUS_ACTOR_MAX = 0.25
BONUS_IDENTIFICADOR = 0.20
BONUS_CORROBORACION = 0.15


@dataclass
class Hallazgo:
    fuente: str
    url: str
    oracion: str
    terminos: list[str]
    actores: list[str]
    categorias: list[str]
    riesgo_intrinseco: float          # 0..1, independiente de la fuente
    contexto_tecnico: bool
    identificadores: list[str]
    puntuaciones: dict[str, float] = field(default_factory=dict)
    impacto: float = 0.0              # aporte al acumulado global
    severidad: str = "BAJO"
    riesgo_desc: str = ""
    mitigacion: str = ""
    pretexto: str = ""                # accion concreta viable para el atacante
    confirmaciones: int = 1
    secretos: list[str] = field(default_factory=list)   # Integrado Social Eye
    piezas_kit: list[str] = field(default_factory=list) # Integrado Social Eye


@dataclass
class ResultadoAnalisis:
    pvi: float = 0.0
    pvi_bruto: float = 0.0
    hallazgos: list[Hallazgo] = field(default_factory=list)
    cobertura: float = 0.0            # 0..1 fuentes que respondieron
    confianza: str = "BAJA"
    por_fuente: dict[str, float] = field(default_factory=dict)
    por_categoria: dict[str, float] = field(default_factory=dict)
    descartes: list[dict[str, str]] = field(default_factory=list)
    fuentes_ok: list[str] = field(default_factory=list)
    fuentes_fallidas: list[dict[str, str]] = field(default_factory=list)
    stack_verificado: list[str] = field(default_factory=list)
    reconocimiento_tecnico: list[dict[str, str]] = field(default_factory=list)
    piezas_cubiertas: list[str] = field(default_factory=list) # Integrado Social Eye
    aportes_tecnicos: dict[str, float] = field(default_factory=dict)

    @property
    def estado(self) -> str:
        if self.pvi >= 70:
            return "RIESGO ALTO"
        if self.pvi >= 35:
            return "RIESGO MEDIO"
        return "RIESGO BAJO"


def _factor_frescura_temporal(texto: str) -> float:
    """Penaliza hallazgos explicitamente antiguos (<= 2022) que pierden urgencia operativa."""
    if not texto:
        return 1.0
    anios = [int(a) for a in re.findall(r"\b(20[12]\d)\b", texto)]
    if not anios:
        return 1.0
    anio_max = max(anios)
    if anio_max <= 2022:
        return 0.80
    return 1.0


def calcular_riesgo_intrinseco(categorias: dict[str, list[str]],
                                contexto_tecnico: bool,
                                tiene_actor: bool,
                                identificadores: list[str],
                                texto: str = "",
                                tiene_secreto: bool = False) -> float:
    """
    Riesgo intrinseco del hallazgo (0..1), INDEPENDIENTE de la fuente.
    Incluye sinergia por Triada de Pretexto, Secret Scanning y frescura temporal.
    """
    if not categorias and not tiene_secreto:
        return 0.0
    if tiene_secreto:
        return 0.99
    pesos = sorted((MULTIPLICADORES.get(c, 0.3) for c in categorias), reverse=True)
    acumulado = 1.0
    for w in pesos:
        acumulado *= (1.0 - min(0.95, max(0.0, w)))
    base = 1.0 - acumulado

    bonus = 0.0
    if tiene_actor:
        bonus += BONUS_ACTOR_MAX
    if identificadores:
        bonus += BONUS_IDENTIFICADOR
    if contexto_tecnico:
        bonus += 0.10

    cats_set = set(categorias.keys())
    tiene_diana = tiene_actor or bool(cats_set & {"ROL_ALTO", "CONTACTO_DIRECTO", "METADATOS_DOC"})
    tiene_proceso = "PROCESO_ALTO" in cats_set
    tiene_stack = "SOFTWARE" in cats_set
    if tiene_diana and tiene_proceso and tiene_stack:
        bonus += 0.15

    riesgo_combinado = base + bonus * (1.0 - base)
    riesgo_ajustado = riesgo_combinado * _factor_frescura_temporal(texto)
    return round(min(0.99, riesgo_ajustado), 4)


def clasificar_severidad(riesgo: float) -> str:
    """Severidad en base al riesgo intrinseco (no al impacto ponderado)."""
    if riesgo >= 0.75:
        return "ALTO"
    if riesgo >= 0.45:
        return "MEDIO"
    return "BAJO"


def pvi_a_riesgo(impacto: float) -> str:
    """Clasificacion legacy conservada para compatibilidad."""
    return "ALTO" if impacto >= 10 else ("MEDIO" if impacto >= 6 else "BAJO")


# ---------------------------------------------------------------------------
# 7. DIAGNOSTICO Y MITIGACION POR CATEGORIA
# ---------------------------------------------------------------------------

_DIAGNOSTICOS: list[tuple[tuple[str, ...], str, str]] = [
    (
        ("CRITICO",),
        "Exposicion de rutas administrativas, endpoints o parametros de configuracion "
        "que facilita el reconocimiento tecnico previo a un pretexto de soporte.",
        "Restringir el acceso con autenticacion robusta y MFA, rotar secretos "
        "expuestos y eliminar rutas sensibles de robots.txt y del indice del sitio.",
    ),
    (
        ("CONTACTO_DIRECTO",),
        "Datos de contacto o credenciales de acceso del objetivo publicados en un "
        "canal abierto: vector directo para spear phishing y suplantacion de identidad.",
        "Reducir la exposicion de datos personales, publicar un canal de reporte "
        "alternativo y activar verificacion de identidad en doble canal.",
    ),
    (
        ("SOFTWARE", "PROCESO_ALTO"),
        "La combinacion de stack tecnologico y proceso de negocio permite construir "
        "un pretexto creible de soporte o consultoria externa.",
        "Anonimizar tecnologias y proveedores criticos en comunicados de prensa y "
        "publicaciones de empleados.",
    ),
    (
        ("ROL_ALTO", "PROCESO_ALTO"),
        "Exposicion de la estructura organizacional y de los flujos administrativos "
        "util para fraude dirigido a finanzas, compras o RRHH.",
        "Capacitar a las areas expuestas en verificacion de identidad de doble canal "
        "ante solicitudes urgentes.",
    ),
    (
        ("ROL_ALTO",),
        "Se expone la estructura de roles y responsables, util para identificar la "
        "persona objetivo y ejecutar un pretexto jerarquico.",
        "Revisar la presencia institucional en redes profesionales y limitar la "
        "publicacion de organigramas y contactos internos.",
    ),
    (
        ("PROCESO_ALTO",),
        "Se detallan procesos internos sensibles que revelan ventanas de "
        "intervencion y volumen de operaciones.",
        "Revisar las politicas de publicacion de informacion operativa y "
        "desensibilizar los casos de negocio publicados.",
    ),
    (
        ("METADATOS_DOC",),
        "Los metadatos de un documento publico identifican a la persona que lo "
        "elaboro y el tipo de documento, permitiendo un phishing dirigido a esa "
        "persona simulando un aviso urgente relacionado con el documento.",
        "Eliminar los metadatos de autor de los documentos publicados, revisar "
        "que los archivos internos no se expongan al indice de buscadores y "
        "sensibilizar a los autores sobre el riesgo.",
    ),
    (
        ("SOFTWARE",),
        "Se revela el stack tecnologico corporativo, util para reconocer "
        "vulnerabilidades conocidas y fabricar incidentes de seguridad.",
        "Reducir la exposicion de detalle tecnico en canales abiertos y en "
        "metadatos de documentos publicados.",
    ),
]


_PRETEXTOS: list[tuple[tuple[str, ...], str]] = [
    (
        ("SOFTWARE", "PROCESO_ALTO"),
        "Llamar al area de soporte o a {actor} haciendose pasar por un tecnico del "
        "proveedor o por el equipo que ejecuta {proceso}, y pedir accesos o "
        "confirmaciones para la implementacion.",
    ),
    (
        ("ROL_ALTO", "PROCESO_ALTO"),
        "Escribir o llamar al area de {rol} haciendose pasar por {actor} para "
        "solicitar datos del proceso en curso, apoyandose en el contexto conocido.",
    ),
    (
        ("METADATOS_DOC",),
        "Enviar un correo de phishing dirigido a {actor} simulando una "
        "actualizacion urgente o una revision del documento '{documento}', "
        "aprovechando que se conoce su autoria y el tipo de archivo.",
    ),
    (
        ("CONTACTO_DIRECTO",),
        "Contactar directamente a {actor} por el medio publicado, haciendose "
        "pasar por soporte de {software} o por un area interna, y pedir "
        "validacion de credenciales o acciones urgentes.",
    ),
    (
        ("PROCESO_ALTO",),
        "Usar el proceso '{proceso}' como pretexto en una llamada al area "
        "involucrada, simulando ser un proveedor o responsable legitimo.",
    ),
    (
        ("ROL_ALTO",),
        "Identificar a {actor} por su rol y dirigir un pretexto jerarquico o "
        "de proveedor para obtener informacion sobre el area.",
    ),
    (
        ("SOFTWARE",),
        "Simular ser del equipo de {software} para pedir una validacion de "
        "acceso, una reinstalacion o una credencial temporal.",
    ),
]

_TERM_PROCESO = {"migracion", "auditoria", "facturacion", "licitacion",
                 "mantenimiento", "proveedor", "contratacion", "despliegue",
                 "actualizacion", "tesoreria", "nomina", "continuidad"}


def _primer_termino(categorias: dict[str, list[str]], objetivo: str) -> str:
    for t in categorias.get(objetivo, []):
        return t
    return ""


def generar_pretexto_viable(hallazgo: "Hallazgo",
                            categorias: dict[str, list[str]],
                            stack_verificado: set[str] | None = None) -> str:
    """Genera el 'pretexto viable para el atacante' cruzando categorias y stack verificado."""
    if hallazgo.secretos:
        return (
            f"Explotar directamente o invocar la filtracion de {', '.join(hallazgo.secretos)} "
            f"simulando una alerta critica del equipo de DevSecOps para forzar la rotacion "
            f"o captura de credenciales."
        )
    cats = set(categorias)
    actores = [a.split(" (")[0] for a in (hallazgo.actores or [])]
    actor = actores[0] if actores else "un responsable interno"
    rol = _primer_termino(categorias, "ROL_ALTO")
    proceso = next((t for t in categorias.get("PROCESO_ALTO", []) if t in _TERM_PROCESO), "")
    software = _primer_termino(categorias, "SOFTWARE")
    if not software and stack_verificado:
        software = sorted(stack_verificado)[0]

    documento = ""
    match = re.search(r"Documento publico: ([^.\n]+)", hallazgo.oracion)
    if match:
        documento = match.group(1).strip()
    match_autor = re.search(
        r"Autor declarado en metadatos:\s*([^.\n]+)", hallazgo.oracion)
    if match_autor:
        actor = match_autor.group(1).strip()

    for requiere, plantilla in _PRETEXTOS:
        if cats.issuperset(requiere):
            return plantilla.format(
                actor=actor,
                rol=rol or "finanzas",
                proceso=proceso or "un proyecto interno",
                software=software or "sistemas",
                documento=documento or "el documento",
            )
    if software:
        return (f"Contactar a {actor} simulando soporte tecnico de {software} "
                f"aprovechando el contexto expuesto para ganar credibilidad.")
    return ("Contactar a " + actor +
            " mencionando el contexto publicado para ganar credibilidad inicial.")


def generar_diagnostico(categorias: Iterable[str],
                        actores: list[str],
                        secretos: list[str] | None = None) -> tuple[str, str]:
    """Diagnostico y mitigacion heuristicos segun las categorias o secretos detectados."""
    if secretos:
        return (
            f"Acceso directo o suplantacion critica mediante credenciales/secretos "
            f"filtrados publicamente ({', '.join(secretos)}).",
            "Revocar y rotar de inmediato la credencial expuesta; eliminarla del "
            "repositorio e historial de commits; activar secret scanning en CI/CD "
            "y almacenar secretos en un Vault o variables de entorno.",
        )
    cats = set(categorias)
    actores_str = ", ".join(actores) if actores else "personal interno"
    for requiere, riesgo, mitigacion in _DIAGNOSTICOS:
        if cats.issuperset(requiere):
            if requiere == ("ROL_ALTO", "PROCESO_ALTO"):
                riesgo = riesgo.replace("(util para", f"({actores_str}, util para")
            return riesgo, mitigacion
    return (
        "Informacion contextual de operaciones que puede usarse para ganar "
        "empatia o credibilidad inicial en un pretexto.",
        "Revisar las politicas de publicacion de informacion operativa en canales abiertos.",
    )


# ---------------------------------------------------------------------------
# 8. ANALISIS DEL CORPUS Y RECALCULO INTERACTIVO
# ---------------------------------------------------------------------------

def _fragmentos(texto: str, sentences) -> list[str]:
    lineas = [l.strip() for l in (texto or "").splitlines() if l.strip()]
    if len(lineas) > 1:
        return lineas
    partes = []
    for sent in sentences:
        t = sent.text.strip()
        if t:
            partes.append(t)
    if not partes:
        for linea in lineas:
            if len(linea) > 15:
                partes.append(linea)
    return partes


def _contexto_tecnico_texto(texto: str) -> bool:
    norm = normalizar(texto)
    if _PATH_RE.search(texto or ""):
        return True
    marcadores = [
        "http://", "https://", "www.", ".com", ".net", ".org", ".io",
        "ruta", "path", "directorio", "servidor", "endpoint", "url", "host",
        "dominio", "archivo", "config", "configuracion", "credencial",
        "usuario", "login", "acceso", "panel", "correo", "email", "api",
        "token", "contrasena", "base de datos", "ftp", "ssh", "sistema",
    ]
    return any(m in norm for m in marcadores)


def _actores_de_fragmento(doc_nlp, frag: str) -> list[str]:
    actores: list[str] = []
    frag_norm = normalizar(frag)
    detalles: list[tuple[int, str]] = []
    for sent in doc_nlp.sents:
        sent_norm = normalizar(sent.text)
        if not sent_norm:
            continue
        if sent_norm in frag_norm or frag_norm in sent_norm:
            for e in sent.ents:
                if e.label_ in ETIQUETAS_ACTOR:
                    detalles.append((sent.start_char, f"{e.text} ({e.label_})"))
    if detalles:
        detalles.sort(key=lambda x: x[0])
        return [d for _, d in detalles]

    mejor, mejor_puntuacion = None, 0.0
    tokens_frag = set(frag_norm.split())
    for sent in doc_nlp.sents:
        tokens_sent = set(normalizar(sent.text).split())
        if not tokens_sent:
            continue
        puntuacion = len(tokens_frag & tokens_sent) / len(tokens_sent)
        if puntuacion > mejor_puntuacion:
            mejor_puntuacion = puntuacion
            mejor = sent
    if mejor is not None and mejor_puntuacion >= 0.30:
        actores = [
            f"{e.text} ({e.label_})"
            for e in mejor.ents
            if e.label_ in ETIQUETAS_ACTOR
        ]
    return actores


def recalcular_resultado_filtrado(resultado_base: ResultadoAnalisis,
                                  indices_conservados: set[int]) -> ResultadoAnalisis:
    """
    Recalcula el PVI, las distribuciones por fuente/categoria y la cobertura
    del Kit de 5 Piezas usando unicamente los hallazgos marcados por el analista
    (funcionalidad interactiva de Social Eye integrada con la formula exponencial).
    """
    conservados = [
        h for i, h in enumerate(resultado_base.hallazgos)
        if i in indices_conservados
    ]
    nuevo = ResultadoAnalisis(
        cobertura=resultado_base.cobertura,
        confianza=resultado_base.confianza,
        descartes=list(resultado_base.descartes),
        fuentes_ok=list(resultado_base.fuentes_ok),
        fuentes_fallidas=list(resultado_base.fuentes_fallidas),
        stack_verificado=list(resultado_base.stack_verificado),
        reconocimiento_tecnico=list(resultado_base.reconocimiento_tecnico),
        aportes_tecnicos=dict(resultado_base.aportes_tecnicos),
        hallazgos=conservados,
    )
    if not conservados:
        return nuevo

    pvi_bruto = 0.0
    por_fuente: dict[str, float] = {}
    por_categoria: dict[str, float] = {}
    piezas_vistas: set[str] = set()

    for h in conservados:
        pvi_bruto += h.impacto
        por_fuente[h.fuente] = round(por_fuente.get(h.fuente, 0.0) + h.impacto, 2)
        for c in h.categorias:
            por_categoria[c] = round(
                por_categoria.get(c, 0.0) + h.riesgo_intrinseco * MULTIPLICADORES.get(c, 0.3),
                2,
            )
        piezas_vistas.update(h.piezas_kit)

    for f_tec, pts_tec in resultado_base.aportes_tecnicos.items():
        pvi_bruto += pts_tec
        por_fuente[f_tec] = round(por_fuente.get(f_tec, 0.0) + pts_tec, 2)
    if "CRITICO" not in por_categoria and resultado_base.aportes_tecnicos:
        por_categoria["ANCLAJE_TECNICO"] = round(sum(resultado_base.aportes_tecnicos.values()), 2)

    pvi = 100.0 * (1.0 - math.exp(-pvi_bruto / K_SATURACION))
    nuevo.pvi = round(min(100.0, pvi), 1)
    nuevo.pvi_bruto = round(pvi_bruto, 2)
    nuevo.por_fuente = dict(sorted(por_fuente.items(), key=lambda kv: -kv[1]))
    nuevo.por_categoria = dict(sorted(por_categoria.items(), key=lambda kv: -kv[1]))
    nuevo.piezas_cubiertas = [p for p in PIEZAS_KIT if p in piezas_vistas]
    return nuevo


def analizar_corpus(items: list[dict[str, Any]], empresa: str, dominio: str,
                    umbral_similitud: float = 0.68,
                    estado_conectores: list[dict[str, str]] | None = None,
                    enmascarar: bool = False) -> ResultadoAnalisis:
    """
    Analiza el corpus recolectado y devuelve el PVI con cobertura, confianza,
    deteccion de secretos y cobertura del Kit de Pretexto (5 piezas).
    """
    nlp = obtener_nlp()
    resultado = ResultadoAnalisis()

    documentos: list[dict[str, Any]] = []
    claves_vistas: set[str] = set()
    for item in items:
        texto_original = str(item.get("texto", "") or "")
        if not texto_original.strip():
            continue
        clave = _clave_dedup(texto_original)
        if clave in claves_vistas:
            resultado.descartes.append({
                "fuente": item.get("fuente", "?"),
                "url": item.get("url", ""),
                "motivo": "documento duplicado",
            })
            continue
        claves_vistas.add(clave)
        documentos.append({**item, "texto": texto_original})

    stack_verificado = extraer_stack_tecnico_verificado(documentos)
    resultado.stack_verificado = sorted(stack_verificado)

    for d in documentos:
        if d.get("fuente") in {
            "Subdominios (Certificados)",
            "DNS / Registros TXT",
            "Robots.txt / Sitemaps",
            "Historico Web (Wayback)",
        }:
            resultado.reconocimiento_tecnico.append({
                "fuente": d.get("fuente", ""),
                "detalle": (d.get("texto", "") or "")[:600],
                "url": d.get("url", ""),
            })

    hallazgos_brutos: list[Hallazgo] = []
    for doc in documentos:
        fuente = doc.get("fuente", "Desconocida")
        url = doc.get("url", "")
        texto = doc.get("texto", "")

        relevante, _conf_relevancia, motivo = evaluar_relevancia(
            texto, empresa, dominio, url
        )
        if not relevante:
            resultado.descartes.append({
                "fuente": fuente, "url": url, "motivo": f"irrelevante: {motivo}",
            })
            continue

        doc_nlp = nlp(texto)
        fragmentos = _fragmentos(texto, doc_nlp.sents)
        if fuente == "OSINT Redes / Dorking" and len(texto) < 600:
            fragmentos = [" ".join(fragmentos)] if fragmentos else []

        tokens_empresa = set(tokens_identificadores(empresa))
        tokens_empresa |= {t for t in tokens_empresa if len(t) > 3}

        if fuente == "Metadatos PDF":
            texto_agrupado = " ".join(fragmentos)
            fragmentos = [texto_agrupado] if texto_agrupado.strip() else []
            m_autor = re.search(
                r"Autor declarado en metadatos:\s*([^.\n]+)", texto_agrupado)
            if m_autor and autor_es_generico(m_autor.group(1).strip()):
                resultado.descartes.append({
                    "fuente": fuente, "url": url,
                    "motivo": "autor generico en metadatos (no identifica a una persona)",
                })
                continue

        for frag in fragmentos:
            # Deteccion de secretos sobre el fragmento original antes de quitar URLs
            secretos_frag = detectar_secretos(frag)
            frag_limpia = limpiar_texto_analizable(frag)
            if len(frag_limpia) < 15 and not secretos_frag:
                continue

            if not secretos_frag and es_ruido_generico(frag_limpia):
                resultado.descartes.append({
                    "fuente": fuente, "url": url,
                    "motivo": "ruido generico (marcas sin contexto social)",
                })
                continue

            if not secretos_frag and es_codigo_fuente(frag_limpia):
                resultado.descartes.append({
                    "fuente": fuente, "url": url,
                    "motivo": "codigo fuente sin contexto social",
                })
                continue

            if not secretos_frag and es_fragmento_esquematico(frag_limpia):
                resultado.descartes.append({
                    "fuente": fuente, "url": url,
                    "motivo": "etiqueta de navegacion sin contexto social",
                })
                continue

            ctx = _contexto_tecnico_texto(frag_limpia) or bool(secretos_frag)
            categorias = detectar_categorias(
                frag_limpia, ctx, excluir=tokens_empresa, doc_nlp=doc_nlp, dominio=dominio
            )
            if secretos_frag:
                categorias.setdefault("CRITICO", []).extend(secretos_frag)
                categorias["CRITICO"] = sorted(set(categorias["CRITICO"]))

            if not categorias:
                continue

            if not secretos_frag and es_enumeracion_tecnica_pura(frag_limpia):
                resultado.descartes.append({
                    "fuente": fuente, "url": url,
                    "motivo": "enumeracion tecnica sin contexto social",
                })
                continue

            if not secretos_frag and not tiene_senal_social(categorias):
                resultado.descartes.append({
                    "fuente": fuente, "url": url,
                    "motivo": "sin senal social habilitante para pretexting",
                })
                continue

            actores = [
                a for a in _actores_de_fragmento(doc_nlp, frag_limpia)
                if not actor_es_generico(a)
                and normalizar(a.split(" (")[0]) not in tokens_empresa
                and normalizar(a.split(" (")[0]) != normalizar(empresa)
            ]
            if fuente == "Metadatos PDF":
                actores = [a for a in actores
                           if not _coincide_con_nombre_documento(a, frag_limpia)]
            identificadores = extraer_identificadores_directos(frag_limpia, dominio)
            if identificadores:
                actores.extend(identificadores)

            terminos = sorted({t for ts in categorias.values() for t in ts})
            riesgo = calcular_riesgo_intrinseco(
                categorias, ctx, bool(actores), identificadores,
                texto=frag_limpia, tiene_secreto=bool(secretos_frag),
            )
            if riesgo <= 0:
                continue

            actores_unicos = sorted(set(actores))
            if enmascarar:
                actores_unicos = [enmascarar_actor(a) for a in actores_unicos]
                oracion_final = enmascarar_texto_sensible(frag_limpia)
            else:
                oracion_final = frag_limpia

            riesgo_desc, mitigacion = generar_diagnostico(
                categorias.keys(), actores_unicos, secretos=secretos_frag
            )
            piezas_hallazgo = mapear_piezas_kit(
                categorias.keys(), terminos, actores_unicos, secretos_frag,
                texto_norm=normalizar(frag_limpia),
            )
            hallazgo = Hallazgo(
                fuente=fuente,
                url=url,
                oracion=oracion_final,
                terminos=terminos,
                actores=actores_unicos,
                categorias=sorted(categorias.keys()),
                riesgo_intrinseco=riesgo,
                contexto_tecnico=ctx,
                identificadores=identificadores,
                riesgo_desc=riesgo_desc,
                mitigacion=mitigacion,
                secretos=secretos_frag,
                piezas_kit=piezas_hallazgo,
            )
            hallazgo.pretexto = generar_pretexto_viable(
                hallazgo, categorias, stack_verificado=stack_verificado
            )
            hallazgos_brutos.append(hallazgo)

    grupos: list[list[Hallazgo]] = []
    for h in hallazgos_brutos:
        encontrado = None
        for g in grupos:
            es_mismo_tema = False
            for m in g:
                umbral_efectivo = 0.72 if m.fuente == h.fuente else umbral_similitud
                if similitud_tematica(m.oracion, h.oracion) >= umbral_efectivo:
                    es_mismo_tema = True
                    break
            if es_mismo_tema:
                encontrado = g
                break
        if encontrado is None:
            grupos.append([h])
        else:
            encontrado.append(h)

    hallazgos_finales: list[Hallazgo] = []
    pvi_bruto = 0.0
    por_fuente: dict[str, float] = {}
    por_categoria: dict[str, float] = {}
    conteo_por_fuente: dict[str, int] = {}
    piezas_globales: set[str] = set()

    grupos.sort(key=lambda g: max(h.riesgo_intrinseco for h in g), reverse=True)

    for grupo in grupos:
        principal = max(grupo, key=lambda h: h.riesgo_intrinseco)
        confirmaciones = len({h.fuente for h in grupo})
        principal.confirmaciones = confirmaciones

        cfg_fuente = PESOS_FUENTE.get(principal.fuente, PESO_FUENTE_POR_DEFECTO)
        peso = cfg_fuente["peso"]
        confianza = cfg_fuente["confianza"]

        n_previos = conteo_por_fuente.get(principal.fuente, 0)
        conteo_por_fuente[principal.fuente] = n_previos + 1
        amortiguacion_fuente = 0.55 ** n_previos

        factor_conf = 1.0 + min(BONUS_CORROBORACION, 0.05 * (confirmaciones - 1))
        impacto = (
            principal.riesgo_intrinseco
            * peso
            * confianza
            * factor_conf
            * amortiguacion_fuente
        )
        acumulado_fuente = por_fuente.get(principal.fuente, 0.0)
        if acumulado_fuente + impacto > 14.0:
            impacto = max(0.25, 14.0 - acumulado_fuente)

        principal.impacto = round(impacto, 2)
        principal.severidad = clasificar_severidad(principal.riesgo_intrinseco)
        pvi_bruto += principal.impacto

        por_fuente[principal.fuente] = round(
            por_fuente.get(principal.fuente, 0.0) + principal.impacto, 2
        )
        for c in principal.categorias:
            por_categoria[c] = round(
                por_categoria.get(c, 0.0)
                + principal.riesgo_intrinseco * MULTIPLICADORES.get(c, 0.3),
                2,
            )
        piezas_globales.update(principal.piezas_kit)
        hallazgos_finales.append(principal)

    if hallazgos_finales:
        aportes_tec = calcular_anclaje_tecnico(documentos)
        resultado.aportes_tecnicos = dict(aportes_tec)
        for f_tec, pts_tec in aportes_tec.items():
            pvi_bruto += pts_tec
            por_fuente[f_tec] = round(por_fuente.get(f_tec, 0.0) + pts_tec, 2)
        if "CRITICO" not in por_categoria and aportes_tec:
            por_categoria["ANCLAJE_TECNICO"] = round(sum(aportes_tec.values()), 2)
        if aportes_tec:
            piezas_globales.add("jerga")

    pvi = 100.0 * (1.0 - math.exp(-pvi_bruto / K_SATURACION))
    resultado.pvi = round(min(100.0, pvi), 1)
    resultado.pvi_bruto = round(pvi_bruto, 2)
    resultado.hallazgos = sorted(
        hallazgos_finales, key=lambda h: h.impacto, reverse=True
    )
    resultado.por_fuente = dict(sorted(por_fuente.items(), key=lambda kv: -kv[1]))
    resultado.por_categoria = dict(sorted(por_categoria.items(), key=lambda kv: -kv[1]))
    resultado.piezas_cubiertas = [p for p in PIEZAS_KIT if p in piezas_globales]

    fuentes_esperadas = set(PESOS_FUENTE.keys())
    fuentes_vistas = {d.get("fuente") for d in documentos}
    resultado.fuentes_ok = sorted(fuentes_vistas & fuentes_esperadas)

    if estado_conectores and len(estado_conectores) > 1:
        conectores_respondieron = sum(
            1 for e in estado_conectores if e.get("estado") in ("ok", "vacio")
        )
        cobertura_red = conectores_respondieron / len(estado_conectores)
        cobertura_doc = len(resultado.fuentes_ok) / max(1, len(fuentes_esperadas))
        resultado.cobertura = round(min(1.0, max(cobertura_red, cobertura_doc)), 3)
        resultado.fuentes_fallidas = [
            e for e in estado_conectores if e.get("estado") == "error"
        ]
    else:
        resultado.cobertura = round(
            min(1.0, len(resultado.fuentes_ok) / max(1, len(fuentes_esperadas))), 3
        )

    densidad = min(1.0, len(resultado.hallazgos) / 8.0)
    nivel = 0.6 * resultado.cobertura + 0.4 * densidad
    if nivel >= 0.66:
        resultado.confianza = "ALTA"
    elif nivel >= 0.33:
        resultado.confianza = "MEDIA"
    else:
        resultado.confianza = "BAJA"

    return resultado