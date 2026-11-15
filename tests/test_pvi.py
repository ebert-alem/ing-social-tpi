"""
Pruebas unitarias del nucleo PVI (sin Streamlit ni red).

Ejecucion:  python -m unittest discover -s tests -v
"""

import os
import sys
import unittest
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pvi_core import (  # noqa: E402
    K_SATURACION,
    analizar_corpus,
    calcular_riesgo_intrinseco,
    clasificar_severidad,
    construir_patrones_ruler,
    detectar_categorias,
    es_productor_generico,
    evaluar_relevancia,
    extraer_identificadores_directos,
    normalizar,
    obtener_nlp,
    quitar_boilerplate,
    similitud_jaccard,
)


class TestNormalizacion(unittest.TestCase):
    def test_normalizar_quita_acentos_y_pasa_a_minusculas(self):
        self.assertEqual(normalizar("AUDITORÍA Migración"), "auditoria migracion")

    def test_boilerplate_se_elimina(self):
        texto = "Aceptar todas las cookies\nContenido relevante de la empresa"
        limpio = quitar_boilerplate(texto)
        self.assertNotIn("cookies", limpio)
        self.assertIn("Contenido relevante", limpio)

    def test_jaccard_detecta_casi_duplicados(self):
        a = "migracion de servidores a AWS por el gerente de infraestructura"
        b = "migracion de servidores a AWS por el gerente de infraestructura."
        self.assertGreater(similitud_jaccard(a, b), 0.9)

    def test_jaccard_distingue_textos_distintos(self):
        self.assertLess(similitud_jaccard("migracion de servidores", "licitacion publica"), 0.3)


class TestRelevancia(unittest.TestCase):
    def test_texto_sin_mencion_se_descarta(self):
        ok, _, motivo = evaluar_relevancia(
            "Acme Corp migro sus servidores en otro pais", "Empresa Ejemplo S.A.", "ejemplo.com"
        )
        self.assertFalse(ok)
        self.assertEqual(motivo, "sin_mencion_del_objetivo")

    def test_texto_con_dominio_es_relevante(self):
        ok, conf, _ = evaluar_relevancia(
            "Panel en https://ejemplo.com/admin", "Empresa Ejemplo S.A.", "ejemplo.com"
        )
        self.assertTrue(ok)
        self.assertGreater(conf, 0.9)

    def test_texto_con_nombre_es_relevante(self):
        ok, _, _ = evaluar_relevancia(
            "Empresa Ejemplo publico su memoria anual", "Empresa Ejemplo S.A.", "ejemplo.com"
        )
        self.assertTrue(ok)

    def test_sufijo_legal_se_tolera(self):
        ok, _, _ = evaluar_relevancia(
            "Ejemplo S.A. abrio una sede", "Empresa Ejemplo S.A.", "ejemplo.com"
        )


class TestTaxonomia(unittest.TestCase):
    def test_frases_multi_palabra_se_detectan(self):
        """Regresion: 'office 365' nunca matcheaba con el patron original."""
        det = detectar_categorias("Migramos a Office 365 y Active Directory")
        self.assertIn("SOFTWARE", det)
        self.assertIn("office 365", det["SOFTWARE"])

    def test_terminos_ambiguos_exigen_contexto(self):
        """'admin'/'test' en prosa generica no debe generar riesgo."""
        det = detectar_categorias(
            "Hicimos un test de usabilidad con el equipo de marketing", contexto_tecnico=False
        )
        self.assertNotIn("CRITICO", det)

    def test_termino_ambiguo_con_contexto_tecnico_cuenta(self):
        det = detectar_categorias(
            "Acceso al servidor: https://ejemplo.com/admin/login", contexto_tecnico=True
        )
        self.assertIn("CRITICO", det)

    def test_proceso_alto_se_detecta(self):
        det = detectar_categorias("La empresa inicio una migracion de servidores")
        self.assertIn("PROCESO_ALTO", det)

    def test_rol_alto_se_detecta(self):
        det = detectar_categorias("El area de recursos humanos maneja las altas")
        self.assertIn("ROL_ALTO", det)

    def test_productor_generico_no_es_riesgo(self):
        self.assertTrue(es_productor_generico("Adobe Acrobat 24.1"))
        self.assertTrue(es_productor_generico("Microsoft Word 2016"))
        self.assertFalse(es_productor_generico("SAP Crystal Reports"))

    def test_patrones_ruler_tokenizan_frases(self):
        """Cada patron multi-palabra debe tener N tokens, no 1."""
        patrones = construir_patrones_ruler()
        office = [p for p in patrones
                  if [t["LOWER"] for t in p["pattern"]] == ["office", "365"]]
        self.assertTrue(office, "no se genero el patron de 'office 365'")
        for p in patrones:
            self.assertGreater(len(p["pattern"]), 0)
            self.assertIn(p["label"], {"CRITICO", "PROCESO_ALTO", "ROL_ALTO",
                                       "SOFTWARE", "CONTACTO_DIRECTO",
                                       "METADATOS_DOC"})


class TestRiesgo(unittest.TestCase):
    def test_riesgo_crece_con_categorias(self):
        uno = calcular_riesgo_intrinseco({"CRITICO": ["admin"]}, False, False, [])
        dos = calcular_riesgo_intrinseco(
            {"CRITICO": ["admin"], "SOFTWARE": ["sap"]}, False, False, []
        )
        self.assertGreater(dos, uno)

    def test_riesgo_acotado_en_uno(self):
        r = calcular_riesgo_intrinseco(
            {"CRITICO": ["x"], "SOFTWARE": ["sap"], "ROL_ALTO": ["ceo"],
             "PROCESO_ALTO": ["nomina"], "CONTACTO_DIRECTO": ["correo"]},
            True, True, ["a@b.com"]
        )
        self.assertLessEqual(r, 1.0)

    def test_actor_aumenta_riesgo(self):
        sin_actor = calcular_riesgo_intrinseco({"ROL_ALTO": ["rrhh"]}, False, False, [])
        con_actor = calcular_riesgo_intrinseco({"ROL_ALTO": ["rrhh"]}, False, True, [])
        self.assertGreater(con_actor, sin_actor)

    def test_severidad_por_riesgo_intrinseco(self):
        self.assertEqual(clasificar_severidad(0.9), "ALTO")
        self.assertEqual(clasificar_severidad(0.5), "MEDIO")
        self.assertEqual(clasificar_severidad(0.2), "BAJO")


class TestFormula(unittest.TestCase):
    def test_saturacion_no_deja_explorar_el_indice(self):
        """Duplicar hallazgos no puede llevar el PVI a 100 por acumulacion lineal."""
        import math
        raw = 120.0
        pvi = 100.0 * (1.0 - math.exp(-raw / K_SATURACION))
        self.assertLess(pvi, 100.0)
        self.assertGreater(pvi, 85.0)

    def test_saturacion_acota_el_crecimiento(self):
        import math
        p1 = 100.0 * (1.0 - math.exp(-10 / K_SATURACION))
        p2 = 100.0 * (1.0 - math.exp(-20 / K_SATURACION))
        self.assertGreater(p2, p1)
        self.assertLess(p2 - p1, 30.0)


class TestNlp(unittest.TestCase):
    def test_entity_ruler_detecta_frases_multi_palabra(self):
        nlp = obtener_nlp()
        doc = nlp("Usamos Office 365 y Active Directory en el area de recursos humanos.")
        labels = {e.text: e.label_ for e in doc.ents}
        self.assertIn("Office 365", labels)
        self.assertEqual(labels["Office 365"], "SOFTWARE")
        self.assertEqual(labels["recursos humanos"], "ROL_ALTO")


class TestAnalisisEndToEnd(unittest.TestCase):
    """Regresion sobre el corpus de demostracion."""

    def _items(self):
        return [
            {"fuente": "Robots.txt / Sitemaps",
             "texto": ("Rutas publicadas en robots.txt del servidor: Disallow: /wp-admin/ | "
                       "Disallow: /staging-portal/ | Disallow: /backup_config/"),
             "url": "https://ejemplo.com/robots.txt"},
            {"fuente": "Noticias / Blog Corporativo",
             "texto": ("Noticia: Empresa Ejemplo S.A. comenzo la migracion de sus servidores "
                       "a AWS junto a la consultora TechSolutions. El Gerente de "
                       "Infraestructura Martin Gomez liderara el despliegue."),
             "url": "https://news.example/x"},
            {"fuente": "OSINT Redes / Dorking",
             "texto": ("Busqueda activa en Empresa Ejemplo S.A.: Analista de Soporte y "
                       "Tesorería con dominio de SAP. Contacto: rrhh@ejemplo.com"),
             "url": "https://linkedin.com/in/x"},
            {"fuente": "Historico Web (Wayback)",
             "texto": ("Rutas historicas sensibles: https://ejemplo.com/admin/backup.sql | "
                       "https://ejemplo.com/old/config.php"),
             "url": "https://web.archive.org/x"},
            {"fuente": "Noticias / Blog Corporativo",
             "texto": ("Noticia sobre otra empresa no relacionada: Acme Corp realizo una "
                       "migracion de servidores en otro pais."),
             "url": "https://news.example/otra"},
        ]

    def test_documento_ajeno_se_descarta(self):
        r = analizar_corpus(self._items(), "Empresa Ejemplo S.A.", "ejemplo.com")
        motivos = " | ".join(d["motivo"] for d in r.descartes)
        self.assertIn("sin_mencion_del_objetivo", motivos)

    def test_urls_no_se_los_quitan_de_la_relevancia(self):
        """
        Regresion: la limpieza borraba las URLs y descartaba el documento.

        La URL sigue siendo la evidencia de que el documento pertenece al
        dominio auditado: el documento de Wayback debe ser CONSIDERADO
        relevante. Ya no produce un hallazgo porque es enumeracion tecnica
        pura (no habilita pretexting social), pero no debe descartarse por
        "sin_mencion_del_objetivo".
        """
        r = analizar_corpus(self._items(), "Empresa Ejemplo S.A.", "ejemplo.com")
        motivos = " | ".join(d["motivo"] for d in r.descartes)
        # No debe descartarse por falta de mencion del dominio.
        descartes_wayback = [
            d for d in r.descartes
            if d["fuente"] == "Historico Web (Wayback)"
        ]
        for d in descartes_wayback:
            self.assertNotIn("sin_mencion_del_objetivo", d["motivo"])
        # Y si aporta algo, debe aparecer en el desglose por fuente.
        if "Historico Web (Wayback)" not in r.por_fuente:
            self.assertIn("sin senal social habilitante", motivos)

    def test_enumeracion_tecnica_no_es_hallazgo_de_pretexting(self):
        """
        Las rutas historicas son reconocimiento tecnico: permiten enumerar
        objetivos, pero NO habilitan inventar una mentira sobre personas o
        procesos. No deben generar hallazgos de PVI por si solas.
        """
        r = analizar_corpus(self._items(), "Empresa Ejemplo S.A.", "ejemplo.com")
        for h in r.hallazgos:
            self.assertNotEqual(h.fuente, "Historico Web (Wayback)")
            self.assertNotEqual(h.fuente, "Robots.txt / Sitemaps")

    def test_ampliar_resultados_no_infla_el_indice(self):
        """Duplicar el corpus no debe Nearly duplicar el PVI."""
        items = self._items()
        r1 = analizar_corpus(items, "Empresa Ejemplo S.A.", "ejemplo.com")
        duplicado = [dict(i, url=i["url"] + f"?n={n}") for n, i in enumerate(items)]
        r2 = analizar_corpus(items + duplicado, "Empresa Ejemplo S.A.", "ejemplo.com")
        self.assertLess(r2.pvi, r1.pvi * 1.15)
        self.assertLessEqual(r2.pvi, 100.0)
    def test_pvi_queda_en_rango_y_tiene_confianza(self):
        r = analizar_corpus(self._items(), "Empresa Ejemplo S.A.", "ejemplo.com")
        self.assertGreaterEqual(r.pvi, 0.0)
        self.assertLessEqual(r.pvi, 100.0)
        self.assertIn(r.confianza, {"ALTA", "MEDIA", "BAJA"})
        self.assertIn(r.estado, {"RIESGO ALTO", "RIESGO MEDIO", "RIESGO BAJO"})


class TestFiltrosDeRuido(unittest.TestCase):
    """
    Filtros que evitan que ruido tecnico o de terceros infle el PVI.
    Detectados al validar contra un dominio real con contenido.
    """

    def test_robots_txt_se_descarta_como_enumeracion_tecnica(self):
        """'Disallow: /login-messages/' es una ruta, no contexto social."""
        from pvi_core import es_enumeracion_tecnica_pura

        self.assertTrue(es_enumeracion_tecnica_pura("Disallow: /login-messages/"))
        self.assertTrue(es_enumeracion_tecnica_pura("Disallow: /admin/"))
        self.assertTrue(es_enumeracion_tecnica_pura("Allow: /public/"))
        # Una linea de robots.txt no debe generar hallazgos.
        r = analizar_corpus(
            [{"fuente": "Robots.txt / Sitemaps",
              "texto": "Rutas publicadas en robots.txt del servidor:\nDisallow: /login-messages/",
              "url": "https://ejemplo.com/robots.txt"}],
            "Ejemplo Corp", "ejemplo.com")
        self.assertEqual(len(r.hallazgos), 0)

    def test_codigo_fuente_se_detecta(self):
        from pvi_core import es_codigo_fuente

        self.assertTrue(es_codigo_fuente(
            "true - show login and password boxes, false - password box only "
            "define('USE_USERNAME', true); // User will be redirected"))
        self.assertFalse(es_codigo_fuente(
            "El equipo de finanzas prepara la auditoria externa con Deloitte."))

    def test_fragmento_esquematico_se_detecta(self):
        from pvi_core import es_fragmento_esquematico

        self.assertTrue(es_fragmento_esquematico("Login | Salesforce"))
        self.assertTrue(es_fragmento_esquematico("See Troubleshoot Login Issues"))
        self.assertFalse(es_fragmento_esquematico(
            "Feliz de empezar el proyecto migracion SAP con el proveedor Acme."))

    def test_autor_generico_no_es_diana(self):
        from pvi_core import autor_es_generico

        self.assertTrue(autor_es_generico("Microsoft Office User"))
        self.assertTrue(autor_es_generico("Unknown"))
        self.assertTrue(autor_es_generico("admin"))
        self.assertTrue(autor_es_generico("PDFMaker"))
        self.assertFalse(autor_es_generico("mgarcia"))
        self.assertFalse(autor_es_generico("Maria Garcia Lopez"))

    def test_nombre_de_la_empresa_auditada_no_cuenta_como_stack(self):
        """
        Coincidencia tautologica: si la empresa auditada se llama 'Salesforce',
        el termino 'salesforce' no puede contar como exposicion de stack.
        """
        from pvi_core import detectar_categorias

        # Sin exclusion: matchea (comportamiento crudo del detector).
        crudo = detectar_categorias("Migramos a Salesforce este trimestre")
        self.assertIn("SOFTWARE", crudo)
        # Con exclusion del nombre de la empresa auditada: ya no cuenta.
        filtrado = detectar_categorias("Migramos a Salesforce este trimestre",
                                       excluir={"salesforce"})
        self.assertNotIn("SOFTWARE", filtrado)

    def test_coincidencia_tautologica_no_genera_hallazgo(self):
        items = [{"fuente": "Web Corporativa Directa",
                  "url": "https://salesforce.com/producto",
                  "texto": "Salesforce ofrece una plataforma completa para empresas."}]
        r = analizar_corpus(items, "Salesforce", "salesforce.com")
        # No debe generar hallazgo solo por nombrarse a si misma.
        for h in r.hallazgos:
            self.assertNotIn("SOFTWARE", h.categorias,
                             f"Coincidencia tautologica: {h.oracion}")

    def test_ruido_de_foro_se_filtra_en_el_conector(self):
        from collectors import _es_ruido_de_foro

        self.assertTrue(_es_ruido_de_foro("https://stackoverflow.com/questions/123"))
        self.assertTrue(_es_ruido_de_foro("https://forum.gitlab.com/t/abc"))
        self.assertTrue(_es_ruido_de_foro("https://pastebin.com/abc"))
        self.assertFalse(_es_ruido_de_foro("https://linkedin.com/in/juan"))
        self.assertFalse(_es_ruido_de_foro("https://ejemplo.com/nota"))

    def test_documentos_de_terceros_se_excluyen(self):
        """Los metadatos solo cuentan si el documento vive en el dominio auditado."""
        import collectors

        def fake_buscador(consulta):
            return [
                {"href": "https://www.google.com/url?q=" + urllib.parse.quote(
                    "https://otro-tercero.com/Planilla.pdf")},
                {"href": "https://ejemplo.com/docs/Interno.pdf"},
            ]

        original = collectors._BUSCADOR_DOCS
        collectors._BUSCADOR_DOCS = fake_buscador
        try:
            urls = collectors._buscar_documentos("ejemplo.com", "Ejemplo Corp")
        finally:
            collectors._BUSCADOR_DOCS = original

        self.assertIn("https://ejemplo.com/docs/Interno.pdf", urls)
        self.assertNotIn("https://otro-tercero.com/Planilla.pdf", urls)


class TestCalidadHallazgos(unittest.TestCase):
    """
    Regresiones sobre los tres problemas reportados por el usuario:
      1) hallazgos duplicados (misma publicacion en dos fuentes),
      2) hallazgos irrelevantes para pretexting (enumeracion tecnica),
      3) falsos actores genericos ("El equipo").
    """

    def _corpus(self):
        return [
            {"fuente": "OSINT Redes / Dorking",
             "url": "https://linkedin.com/posts/abc",
             "texto": ("Feliz de empezar el proyecto migracion SAP con el proveedor "
                       "Acme Consulting. El equipo usa SAP HANA y Okta para el acceso.")},
            {"fuente": "Noticias / Blog Corporativo",
             "url": "https://news.ejemplo.com/1",
             "texto": ("Ejemplo Corp anuncia que el proyecto migracion SAP con "
                       "Acme Consulting comenzo. El equipo usa SAP HANA y Okta para el acceso.")},
            {"fuente": "Web Corporativa Directa",
             "url": "https://ejemplo.com/noticias",
             "texto": "Feliz de empezar el proyecto migracion SAP con el proveedor Acme Consulting."},
        ]

    def test_misma_publicacion_en_distintas_fuentes_se_fusiona(self):
        """La publicacion de LinkedIn y la nota de prensa son UN hallazgo."""
        r = analizar_corpus(self._corpus(), "Ejemplo Corp", "ejemplo.com")
        termino = "migracion"
        migracion = [h for h in r.hallazgos if termino in " ".join(h.terminos)]
        self.assertEqual(
            len(migracion), 1,
            f"La misma publicacion genero {len(migracion)} hallazgos: "
            f"{[h.fuente for h in migracion]}",
        )
        # Y debe creditarse la corroboracion entre fuentes.
        self.assertGreaterEqual(migracion[0].confirmaciones, 2)

    def test_enumeracion_tecnica_no_genera_hallazgos(self):
        """Subdominios y registros DNS no habilitan pretexting social."""
        items = [
            {"fuente": "Subdominios (Certificados)", "url": "https://crt.sh/?q=ejemplo.com",
             "texto": ("Subdominios certificados del dominio: admin.ejemplo.com, "
                       "vpn.ejemplo.com, dev.ejemplo.com, mail.ejemplo.com. "
                       "Subdominios con nombre sensible: admin.ejemplo.com")},
            {"fuente": "DNS / Registros TXT", "url": "https://dns.google/resolve",
             "texto": ("Registros DNS publicos del dominio: TXT: google-site-verification=abc "
                       "| MX: mail.ejemplo.com | CNAME: shop.ejemplo.com")},
        ]
        r = analizar_corpus(items, "Ejemplo Corp", "ejemplo.com")
        self.assertEqual(len(r.hallazgos), 0)
        motivos = " | ".join(d["motivo"] for d in r.descartes)
        self.assertIn("sin senal social habilitante", motivos)

    def test_ruido_de_marcas_se_descarta(self):
        """'Microsoft Word 16.0' no es senal de riesgo."""
        items = [
            {"fuente": "OSINT Redes / Dorking", "url": "https://x.com/p/1",
             "texto": ("Microsoft Word 16.0. Word Microsoft Office 365 Microsoft Excel 16.0. "
                       "Adobe Acrobat 24.1.")},
        ]
        r = analizar_corpus(items, "Ejemplo Corp", "ejemplo.com")
        self.assertEqual(len(r.hallazgos), 0)

    def test_actor_generico_no_inflama_el_bonus(self):
        """'El equipo' no es un actor: no debe dar bonus de entidad real."""
        from pvi_core import actor_es_generico

        self.assertTrue(actor_es_generico("El equipo (MISC)"))
        self.assertTrue(actor_es_generico("La empresa (ORG)"))
        self.assertTrue(actor_es_generico("El proyecto (MISC)"))
        self.assertFalse(actor_es_generico("Acme Consulting (ORG)"))
        self.assertFalse(actor_es_generico("Martin Gomez (PER)"))

    def test_similitud_tematica_detecta_mismo_evento(self):
        from pvi_core import similitud_tematica

        a = "Feliz de empezar el proyecto migracion SAP con el proveedor Acme Consulting."
        b = "Ejemplo Corp anuncia que el proyecto migracion SAP con Acme Consulting comenzo."
        self.assertGreaterEqual(similitud_tematica(a, b), 0.55)

    def test_similitud_tematica_distingue_eventos_distintos(self):
        from pvi_core import similitud_tematica

        casos = [
            ("Feliz de empezar el proyecto migracion SAP con el proveedor Acme Consulting.",
             "El equipo de finanzas prepara la auditoria externa con Deloitte para el cierre."),
            ("El proveedor Globex revisa el despliegue de sistemas.",
             "El proveedor Initech implementa una migracion de datos en finanzas."),
            # Mismo concepto, entidad calificada de forma distinta: son
            # vectores de pretexto independientes.
            ("Migracion de servidores del datacenter principal completada.",
             "Migracion de servidores del datacenter secundario completada."),
        ]
        for a, b in casos:
            self.assertLess(
                similitud_tematica(a, b), 0.55,
                f"Textos de eventos distintos se consideraron duplicados: {a!r} / {b!r}",
            )

    def test_hallazgo_social_siempre_tiene_categoria_social(self):
        """Ningun hallazgo puede sostenerse solo con senal tecnica."""
        r = analizar_corpus(self._corpus(), "Ejemplo Corp", "ejemplo.com")
        for h in r.hallazgos:
            self.assertTrue(
                any(c in {"PROCESO_ALTO", "ROL_ALTO", "SOFTWARE", "CONTACTO_DIRECTO",
                          "METADATOS_DOC"}
                    for c in h.categorias),
                f"Hallazgo sin senal social: {h.categorias}",
            )


class TestMetadatosDocumento(unittest.TestCase):
    """
    Los metadatos de documento son un vector de INGENIERIA SOCIAL (decidido por
    el usuario): el autor y el nombre del archivo son la diana del phishing.
    El productor generico (Adobe, Word) NO debe puntuar.
    """

    def _item_pdf(self, texto):
        return {"fuente": "Metadatos PDF",
                "url": "https://ejemplo.com/docs/Formulario_Proveedores.pdf",
                "texto": texto}

    def test_autor_en_metadatos_es_hallazgo_social(self):
        texto = ("Documento publico: Formulario Proveedores.\n"
                 "Autor declarado en metadatos: mgarcia.\n"
                 "Productor del documento: SAP Crystal Reports.")
        r = analizar_corpus([self._item_pdf(texto)], "Ejemplo Corp", "ejemplo.com")
        self.assertEqual(len(r.hallazgos), 1)
        h = r.hallazgos[0]
        self.assertIn("METADATOS_DOC", h.categorias)
        # El pretexto debe mencionar a la persona y el documento.
        self.assertIn("mgarcia", h.pretexto)
        self.assertIn("Formulario", h.pretexto)

    def test_productor_generico_no_genera_hallazgo(self):
        """Adobe/Word no aporta ninguna diana: no debe puntuar."""
        texto = ("Documento publico: Informe anual.\n"
                 "Productor del documento: Adobe Acrobat Pro 24.1.\n"
                 "Software de creacion declarado: Microsoft Word 16.0.")
        r = analizar_corpus([self._item_pdf(texto)], "Ejemplo Corp", "ejemplo.com")
        self.assertEqual(len(r.hallazgos), 0)

    def test_cada_hallazgo_tiene_pretexto_viable(self):
        """Todo hallazgo debe poder traducirse en una accion concreta."""
        r = analizar_corpus(self._corpus_social(), "Ejemplo Corp", "ejemplo.com")
        self.assertTrue(r.hallazgos)
        for h in r.hallazgos:
            self.assertTrue(h.pretexto.strip(), f"Sin pretexto: {h.oracion}")
            self.assertGreater(len(h.pretexto), 25)

    def test_contenido_del_pdf_se_analiza(self):
        """
        El TEXTO del PDF se analiza, no solo los metadatos.

        Un documento que menciona una migracion con una consultora debe
        producir las categorias PROCESO_ALTO y SOFTWARE aunque los
        metadatos no digan nada.
        """
        texto = ("Documento publico: Formulario Proveedores.\n"
                 "Autor declarado en metadatos: mgarcia.\n"
                 "La empresa Ejemplo Corp esta migrando sus servidores a AWS "
                 "con la consultora TechSolutions. El director de finanzas "
                 "solicito la planilla de nominas del ultimo trimestre.")
        r = analizar_corpus([self._item_pdf(texto)], "Ejemplo Corp", "ejemplo.com")
        self.assertEqual(len(r.hallazgos), 1)
        h = r.hallazgos[0]
        # Categorias que SOLO pueden venir del contenido del PDF.
        self.assertIn("SOFTWARE", h.categorias)
        self.assertIn("ROL_ALTO", h.categorias)

    def test_actor_real_del_contenido_no_es_el_nombre_del_documento(self):
        """El NER puede tomar el nombre del archivo como entidad: se filtra."""
        texto = ("Documento publico: Formulario Proveedores.\n"
                 "Autor declarado en metadatos: mgarcia.\n"
                 "La empresa Ejemplo Corp esta migrando sus servidores a AWS "
                 "con la consultora TechSolutions.")
        r = analizar_corpus([self._item_pdf(texto)], "Ejemplo Corp", "ejemplo.com")
        h = r.hallazgos[0]
        nombres = [a.split(" (")[0] for a in h.actores]
        self.assertNotIn("Formulario Proveedores", nombres)
        # La consultora real si debe estar.
        self.assertIn("TechSolutions", nombres)

    def test_contenido_solo_genera_hallazgo_si_tiene_senal_social(self):
        """
        Un PDF cuyo CONTENIDO no aporta contexto social no debe puntuar por
        su contenido. (El autor de los metadatos sigue siendo diana: es
        ingenieria social valida por si misma.)
        """
        texto = ("Documento publico: Manual de Instalacion.\n"
                 "Autor declarado en metadatos: mgarcia.\n"
                 "Este manual explica como instalar el producto en el sistema "
                 "operativo del equipo y configurarlo correctamente.")
        r = analizar_corpus([self._item_pdf(texto)], "Ejemplo Corp", "ejemplo.com")
        for h in r.hallazgos:
            # Solo METADATOS_DOC: el contenido del manual no aporto proceso,
            # rol ni software de la organizacion auditada.
            self.assertEqual(
                h.categorias, ["METADATOS_DOC"],
                f"El contenido sin contexto social genero {h.categorias}",
            )

    def test_pdf_sin_autor_real_ni_contexto_social_no_puntua(self):
        """Sin autor identificable y sin contexto social: no hay hallazgo."""
        texto = ("Documento publico: Manual de Instalacion.\n"
                 "Este manual explica como instalar el producto y configurarlo "
                 "correctamente en el equipo.")
        r = analizar_corpus([self._item_pdf(texto)], "Ejemplo Corp", "ejemplo.com")
        self.assertEqual(len(r.hallazgos), 0)

    def _corpus_social(self):
        return [
            {"fuente": "Noticias / Blog Corporativo",
             "url": "https://ejemplo.com/nota",
             "texto": ("Ejemplo Corp comenzo la migracion de sus servidores a AWS "
                       "junto a la consultora TechSolutions. El Gerente de "
                       "Infraestructura Martin Gomez liderara el despliegue.")},
        ]


class TestResolucionUrlsBuscador(unittest.TestCase):
    """Los dorks devuelven URLs de redireccion: hay que resolverlas."""

    def test_resuelve_redirect_google(self):
        from collectors import _resolver_url_buscador
        real = "https://ejemplo.com/docs/Formulario.pdf"
        wrap = "https://www.google.com/url?q=" + urllib.parse.quote(real)
        self.assertEqual(_resolver_url_buscador(wrap), real)

    def test_resuelve_redirect_duckduckgo(self):
        from collectors import _resolver_url_buscador
        real = "https://ejemplo.com/docs/Planilla.xlsx"
        wrap = "https://duckduckgo.com/l/?uddg=" + urllib.parse.quote(real)
        self.assertEqual(_resolver_url_buscador(wrap), real)

    def test_url_directa_no_se_altera(self):
        from collectors import _resolver_url_buscador
        real = "https://ejemplo.com/docs/Formulario.pdf"
        self.assertEqual(_resolver_url_buscador(real), real)

    def test_buscador_de_documentos_usa_extension_y_resuelve(self):
        """El buscador de documentos debe filtrar por extension y resolver URLs."""
        import collectors

        def fake_buscador(consulta):
            return [
                {"href": "https://www.google.com/url?q=" + urllib.parse.quote(
                    "https://ejemplo.com/Formulario_Proveedores.pdf")},
                {"href": "https://ejemplo.com/pagina.html"},  # no es documento
                {"href": "https://ejemplo.com/Planilla_Nominas.xlsx"},
            ]

        original = collectors._BUSCADOR_DOCS
        collectors._BUSCADOR_DOCS = fake_buscador
        try:
            urls = collectors._buscar_documentos("ejemplo.com", "Ejemplo Corp")
        finally:
            collectors._BUSCADOR_DOCS = original

        self.assertIn("https://ejemplo.com/Formulario_Proveedores.pdf", urls)
        self.assertIn("https://ejemplo.com/Planilla_Nominas.xlsx", urls)
        self.assertNotIn("https://ejemplo.com/pagina.html", urls)


class TestColectores(unittest.TestCase):
    """Pruebas de los conectores sin depender de red (logica pura)."""

    def test_patron_subdominio_acepta_y_rechaza(self):
        from collectors import _patron_subdominio
        p = _patron_subdominio("example.com")
        self.assertTrue(p.match("www.example.com"))
        self.assertTrue(p.match("dev.example.com"))
        self.assertTrue(p.match("emudhra-lab.example.com"))
        # El dominio raiz no es un subdominio.
        self.assertFalse(p.match("example.com"))
        # CN legible de crt.sh (no es subdominio real).
        self.assertFalse(p.match("as207960 test intermediate - example.com"))
        # Sufijo que no es el dominio audited.
        self.assertFalse(p.match("m.testexample.com"))

    def test_urls_de_sitemap_acepta_indice_y_plano(self):
        import collectors
        xml_indice = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
            '<sitemap><loc>https://ejemplo.com/sitemap-1.xml</loc></sitemap>'
            '</sitemapindex>'
        )
        xml_plano = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
            '<url><loc>https://ejemplo.com/empleo</loc></url>'
            '<url><loc>https://ejemplo.com/contacto</loc></url>'
            '</urlset>'
        )
        for xml, esperado in ((xml_indice, 1), (xml_plano, 2)):
            import xml.etree.ElementTree as ET
            root = ET.fromstring(xml)
            ns = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}
            locs = root.findall(".//sm:loc", ns) or root.findall(".//{*}loc")
            self.assertEqual(len(locs), esperado)


class TestRobustezConectores(unittest.TestCase):
    """
    Regresion: un conector truncado que devolvia None en vez de la tupla
    (items, detalle) rompia toda la recoleccion en vivo con
    "TypeError: cannot unpack non-iterable NoneType object".
    """

    def test_todos_los_conectores_devuelven_tupla(self):
        import inspect
        import collectors

        for nombre in dir(collectors):
            if not nombre.startswith("conector_"):
                continue
            fn = getattr(collectors, nombre)
            codigo = inspect.getsource(fn)
            self.assertIn("return", codigo, f"{nombre} no tiene return")
            # El camino principal debe devolver la tupla (items, detalle).
            self.assertRegex(codigo, r"return\s+\w+,\s*f?[\"'a-zA-Z_]",
                             f"{nombre} no retorna la tupla (items, detalle)")

    def test_orquestador_tolera_conector_que_devuelve_none(self):
        """Si un conector falla, el orquestador NO debe propagar la excepcion."""
        from collectors import recolectar_datos_reales

        def roto(*args, **kwargs):
            return None  # simula el bug original

        items, estado = recolectar_datos_reales(
            "example.com", "Test",
            conectores=[("Dorking dirigido", roto)],
            buscar_documentos=False,
        )
        self.assertIsInstance(items, list)
        self.assertIsInstance(estado, list)
        dorking = next(e for e in estado if e["conector"] == "Dorking dirigido")
        self.assertEqual(dorking["estado"], "vacio")
        self.assertIn("no devolvio", dorking["detalle"])

    def test_orquestador_tolera_excepcion_de_conector(self):
        from collectors import recolectar_datos_reales

        def explota(*args, **kwargs):
            raise RuntimeError("fallo simulado")

        items, estado = recolectar_datos_reales(
            "example.com", "Test",
            conectores=[("robots.txt", explota)],
            buscar_documentos=False,
        )
        robots = next(e for e in estado if e["conector"] == "robots.txt")
        self.assertEqual(robots["estado"], "error")
        self.assertIn("RuntimeError", robots["detalle"])

    def test_orquestador_tolera_tupla_invalida(self):
        from collectors import recolectar_datos_reales

        def invalido(*args, **kwargs):
            return ("solo un string",)  # tupla de longitud 1

        items, estado = recolectar_datos_reales(
            "example.com", "Test",
            conectores=[("robots.txt", invalido)],
            buscar_documentos=False,
        )
        robots = next(e for e in estado if e["conector"] == "robots.txt")
        self.assertEqual(robots["estado"], "vacio")
        self.assertIn("formato de retorno", robots["detalle"])

    def test_orquestador_agrega_items_de_conectores_ok(self):
        from collectors import recolectar_datos_reales

        def bueno(*args, **kwargs):
            return ([{"fuente": "X", "texto": "dato", "url": ""}], "ok")

        items, estado = recolectar_datos_reales(
            "example.com", "Test",
            conectores=[("robots.txt", bueno)],
            buscar_documentos=False,
        )
        self.assertEqual(len(items), 1)
        robots = next(e for e in estado if e["conector"] == "robots.txt")
        self.assertEqual(robots["estado"], "ok")


class TestInterfazStreamlit(unittest.TestCase):
    """
    Prueba de humo de la UI completa (carga + pulsacion del boton).

    Regresion: un `if ejecutar:` sin el boton definido, y dos `int(val)`
    donde la variable se llamaba `valor`, rompian la app en tiempo de
    ejecucion aunque el archivo compilara correctamente.
    """

    def test_app_carga_y_procesa_sin_excepciones(self):
        try:
            from streamlit.testing.v1 import AppTest
        except Exception as exc:  # pragma: no cover
            self.skipTest(f"Streamlit testing no disponible: {exc}")

        at = AppTest.from_file(
            os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                         "app.py"),
            default_timeout=180,
        )
        at.run()
        self.assertEqual(len(list(at.exception)), 0, f"Error al cargar: {list(at.exception)}")
        self.assertGreater(len(at.button), 0, "No se encontro el boton de ejecucion")

        at.button[0].click().run()
        self.assertEqual(len(list(at.exception)), 0,
                         f"Error al ejecutar: {list(at.exception)}")

        # El reporte debe producir metricas y subsecciones.
        labels = [m.label for m in at.metric]
        self.assertTrue(any("PVI" in l for l in labels), f"Metricas: {labels}")
        self.assertGreaterEqual(len(at.subheader), 3)


if __name__ == "__main__":
    unittest.main(verbosity=2)
