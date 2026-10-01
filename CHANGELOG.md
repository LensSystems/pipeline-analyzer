# Historial de cambios

Todos los cambios relevantes de este proyecto se documentan en este archivo.
El formato sigue [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/) y el proyecto usa [versionado semántico](https://semver.org/lang/es/).

## [Sin publicar]

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
