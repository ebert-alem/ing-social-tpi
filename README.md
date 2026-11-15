# Auditor PVI - Ingeniería Social

Herramienta académica en Streamlit para analizar información pública de una organización y estimar su exposición ante posibles pretextos de ingeniería social.

## Requisitos

- Python 3.11 o superior
- Conexión a Internet para la recolección OSINT
- Acceso autorizado a los dominios analizados

## Instalación

Desde la carpeta del proyecto:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m spacy download es_core_news_md
```

Si PowerShell bloquea la activación del entorno:


## Ejecutar la aplicación

No ejecutar con `python app.py`. Streamlit debe iniciarse así:

```powershell
streamlit run app.py
```

Después, abrir la dirección mostrada en la terminal, normalmente:

```text
http://localhost:8501
```

## Prueba rápida

1. Introducir una organización conocida y su dominio, por ejemplo:
   - Organización: `Globant`
   - Dominio: `globant.com`
2. Elegir **Simulación Controlada** para comprobar la interfaz sin depender de servicios externos.
3. Presionar **Ejecutar Análisis PVI (Tarda 1 minuto)**.
4. Revisar:
   - Índice PVI global.
   - Confianza y cobertura de la estimación.
   - Documentos analizados.
   - Hallazgos únicos.
   - Estado individual de cada conector.
5. Para una prueba real, seleccionar **Recolección OSINT en Vivo** y volver a ejecutar el análisis.

La recolección en vivo consulta, entre otras fuentes, robots.txt, sitemaps, certificados, DNS, GitHub, Google News, Wayback Machine, buscadores y documentos públicos.

## Ejecutar las pruebas

```powershell
python -m pytest
```

## Notas

- La recolección puede devolver pocos resultados si una fuente bloquea solicitudes, aplica límites o no tiene información indexada.
- La primera ejecución puede tardar por la carga del modelo de spaCy.
- La información recolectada debe tratarse como evidencia pública y no como confirmación de una vulnerabilidad.
- Usar la herramienta únicamente sobre organizaciones y dominios donde exista autorización.
