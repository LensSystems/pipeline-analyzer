# Historial de cambios

Todos los cambios relevantes de este proyecto se documentan en este archivo.
El formato sigue [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/) y el proyecto usa [versionado semántico](https://semver.org/lang/es/).

## [Sin publicar]

### Cambiado
- **Reporte HTML**: lo que bloquea el pipeline y lo que puede resolver el equipo de desarrollo (resumen, ruta para pasar, resultados de CxOne y hallazgos de Checkmarx) queda siempre visible. El resto (plan de acción, hallazgos del proyecto, comparativa, ejecuciones, archivos revisados, recomendaciones para quien administra el pipeline y validaciones) aparece plegado con su título y un dato breve, y se expande al hacer clic, desde el menú o desde un enlace interno (que abre también la sección que lo contiene). Al imprimir se abren todas.
- Más espacio entre secciones, tarjetas, listas y tablas para que el texto no se vea amontonado.

### Añadido
- **Paso 4 en el asistente** (ventanas y consola): «¿Quieres agregar reportes de las herramientas?», para los reportes (PDF/JSON/XML/Markdown de Checkmarx, PMD, Checkstyle, SpotBugs) que no venían en la carpeta o el `.zip`. Admite varios archivos o carpetas y muestra lo ya agregado.
- **Reporte de Checkmarx One («Scan Report»)**: lectura completa del PDF (o de su conversión a `.md`): información del escaneo, filtros aplicados, cada resultado SAST (consulta, CWE, severidad, estado, origen → destino, método, línea de código y antigüedad), SCA (paquete, versión, CVE y versión corregida) y el detalle de riesgo y recomendaciones.
- **Soluciones propuestas** por hallazgo (Java/Spring/Maven) con ejemplo de código y un veredicto por resultado: *probable falso positivo*, *problema real* o *revisar* (p. ej. contraseña ya inyectada con `${...}` frente a un valor literal).
- Cruce con el log más estricto: ¿mismo escaneo? (ID, rama, hora) y estado de cada motor (detecta, por ejemplo, SCS «Partial» en el log y «Completed» en el reporte).
- Tabla de **Resultados de CxOne** rediseñada: total, chips por severidad, barra proporcional, insignias de color y filas «no ejecutado» atenuadas.
- **Resultados de CxOne** completos en consola, HTML, Markdown y PDF: tabla del «Scan Summary» con APIs, IAC, SAST, SCA, SCS, Containers y Total (Critical/High/Medium/Low/Info y estado; «no ejecutado» si el motor trae `-`), «Total Results», Secret Detection, Scorecard, metadatos del escaneo y notas (lo que el breaker no bloquea, SCS parcial, filtro SAST que excluye `test/`).
- Las verificaciones de CxOne y la comparativa entre ejecuciones incluyen Medium/Low y el total.
- **Revisión completa de carpetas y `.zip`**: los reportes de herramientas (XML/JSON/PDF) se buscan también dentro de `.zip`, y el HTML incluye «Archivos revisados» con el tratamiento de cada archivo (leído, ignorado y por qué).
- Lectura de los **PDF que se descargan de Checkmarx** (SAST, SCA y SCS) con `--reports`, sin dependencias: lector de PDF propio (`pdf_reader.py`) y parser de hallazgos (`cxone_pdf.py`).
- **Cruce PDF ↔ pipeline** en el HTML: conteos por motor y severidad contra el «Scan Summary» del log (con aviso de hallazgos *Not Exploitable*) y, si también hay JSON de CxOne, hallazgo por hallazgo (coinciden / solo PDF / solo JSON).
- `--dump-pdf` para ver el texto que se lee de un PDF y los hallazgos interpretados.

## [1.4.0] - 2026-09-30

Primera versión pública.

### Añadido
- Análisis de logs de **Azure DevOps** (carpeta de descarga o `.zip`, con intentos y re-runs), **GitHub Actions**, **GitLab CI**, **Jenkins** y logs genéricos, con detección automática del proveedor.
- Extracción de métricas por contenido: tests (Maven Surefire, Gradle, Jest/Vitest, pytest, .NET, Go), SonarQube, CxOne, TMAS, Checkstyle/PMD/SpotBugs y otros escáneres (Trivy, Grype, Snyk, npm audit, Dependency-Check, Gitleaks, Semgrep, Checkov).
- Revisión de seguridad: secretos en claro, TLS deshabilitado, `curl | bash`, imágenes mutables, ramas mutables, CVE conocidos, manifiestos de Kubernetes/OpenShift y definición del pipeline.
- Revisión del `pom.xml` (dependencias, plugins, propiedades, repositorios).
- **Ruta para pasar el pipeline**: hallazgos que bloquean agrupados en pasos ordenados, con criterio de «listo cuando» y comandos de validación local.
- Separación entre hallazgos del **proyecto** y recomendaciones para quien administra el **pipeline**, con etiquetas y enlaces cuando uno bloquea al otro.
- Lectura opcional de reportes XML/JSON de PMD, Checkstyle, SpotBugs y CxOne (`--reports`) para mostrar regla, archivo y línea.
- Comparativa entre ejecuciones con tendencia por métrica y diff de hallazgos (resueltos, nuevos, persistentes y no verificables).
- Reportes en consola, HTML, **PDF** (generador propio sin dependencias, con portada, índice, marcadores y enlaces internos), Markdown y JSON, cada uno en versión para compartir y versión completa de uso local.
- Cada análisis se guarda en una carpeta nueva numerada (`NNN_AAAA-MM-DD`) y se genera `historial-reportes.html` con todos los análisis.
- Asistente interactivo con ventanas nativas (tkinter) y modo consola; barra de avance; diagnóstico del entorno (`--doctor`).
- Lanzadores para macOS, Linux y Windows; empaquetado con `pyproject.toml` (`pipeline-analyzer` y `pipeline-analyzer-gui`).
- Flujos de integración continua para GitHub Actions y Azure Pipelines.

### Seguridad y privacidad
- El análisis es 100 % local: la suite verifica que el código no importe módulos de red.
- Secretos enmascarados por defecto en las salidas para compartir; origen de las ejecuciones reducido a la carpeta de logs.

[Sin publicar]: https://github.com/LensSystems/pipeline-analyzer/compare/v1.4.0...HEAD
[1.4.0]: https://github.com/LensSystems/pipeline-analyzer/releases/tag/v1.4.0
