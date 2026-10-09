# Historial de cambios

Todos los cambios relevantes de este proyecto se documentan en este archivo.
El formato sigue [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/) y el proyecto usa [versionado semántico](https://semver.org/lang/es/).

## [Sin publicar]

### Añadido
- **«Solo comparación»** (botón nativo, aparece al elegir el log principal y al menos una comparación; en consola, una pregunta; en CLI, `--compare-only`): genera únicamente el comparativo viejo → nuevo (qué mejoró, empeoró o cambió y qué hallazgos se resolvieron, aparecieron o siguen pendientes), sin pom ni reportes de herramientas. «FALLO» y «NO EJECUTADO» cuentan como lo mismo al comparar. Los reportes HTML, PDF, Markdown y JSON se limitan a eso.
- **Validación de archivos repetidos** (ventanas y consola): el mismo archivo (misma ruta) no se puede usar en dos apartados (log principal, comparación, pom.xml, reportes) ni repetirse; sale «Archivo no válido». El mismo nombre en otra carpeta sí se acepta.
- **Reporte HTML:** enlace «Historial de reportes» en el menú lateral para abrir la lista de todos los análisis sin buscar el archivo.
- **Elegir si se agrega el YAML al análisis** (ventanas y consola): si la carpeta o el `.zip` de una ejecución trae un `.yaml`/`.yml`, aparece debajo de las entradas la casilla «¿Quieres agregar el archivo .yaml al análisis?» (sin marcar por defecto; también visible en «Solo comparación»). Hay una por ejecución; las de comparación dicen «… al análisis de comparación», sin número si hay una y con 1, 2 si hay dos. Al marcar una se marcan y bloquean las demás, y al desmarcarla se liberan, para que los hallazgos sean comparables. En consola se hace la misma pregunta.
- **`--no-yaml`:** omite las definiciones YAML de todas las ejecuciones. Con argumentos, el YAML se sigue incluyendo por defecto.

### Cambiado
- **YAML sin marcar no se analiza** (ventanas y consola): antes el `.yaml`/`.yml` de una carpeta o `.zip` se analizaba siempre; ahora, en modo interactivo, solo se analiza si se marca la casilla o se responde «sí». Los YAML omitidos tampoco figuran como revisados en el reporte.
- **Máximo de 3 ejecuciones** (1 principal y 2 comparaciones) en ventanas, consola y línea de comandos. En las ventanas, «Carpeta…» y «Archivo…» de la fila Comparación se deshabilitan con 2 comparaciones; en la línea de comandos, más de 3 logs terminan con código de salida 2 (antes no había límite).
- **Reporte HTML e historial rediseñados:** títulos con tipografía redondeada del sistema, índice con la sección actual resaltada, filas de las tablas con una marca de color según lo que pasó, y en «Solo comparación» un titular, una barra proporcional y su leyenda. El historial tiene buscador redondeado y etiqueta «Solo comparación».
- **Ventana:** el botón «Quitar» es más pequeño y redondeado, y la ayuda «Doble clic en un archivo para abrirlo» queda justo debajo de la lista de resultados, que se ajusta a su contenido (hasta 8 filas, luego se desplaza).
- **Modo oscuro** con una paleta de azul marino (`#16213e`) en lugar de negro: tarjetas más claras que el fondo, bloques de código más profundos y estados claros teñidos del mismo tono. Se aplica al reporte HTML y al historial; la ventana de la aplicación mantiene el aspecto nativo del sistema.
- **Comparativa más clara en todos los reportes:** con dos ejecuciones la tabla es «Antes · Ahora · Cambio» (ya no se repite «vs anterior» y «vs primera», que eran lo mismo). Primero van las métricas que cambiaron, la peor primero, con la diferencia («Mejoró (-9)»); al final, las que siguen igual, marcadas «Sin cambios». Con tres o más ejecuciones se agrega la columna «Desde la primera». Los hallazgos se agrupan como Resueltos, Nuevos, Siguen pendientes y No verificables, con una explicación breve.

### Corregido
- **Windows: la ventana se cerraba al agregar un archivo.** El botón «Quitar» usaba el cursor `pointinghand`, que solo existe en macOS; Tk en Windows lanzaba un error y la aplicación terminaba sin avisar. Ahora usa `hand2` fuera de macOS, y cualquier fallo inesperado de las ventanas pasa a la consola (o muestra un aviso) en vez de cerrarse en silencio.

### Cambiado (lanzadores)
- **Un solo archivo de arranque en Windows:** `analizar_pipeline.bat` reemplaza a `analizar_pipeline.pyw`. Elige el mejor Python (con ventanas primero) y `analizar_pipeline.py` elige el modo de mejor a peor: ventanas sin consola (pythonw), ventanas con consola, preguntas en la consola y, si no hay nada, un aviso con el motivo.

### Cambiado
- **Ventana en Windows y Linux:** misma pantalla única «Nuevo análisis» que en macOS (reemplaza al asistente de 4 pasos), con el mismo tamaño, el botón «Quitar» naranja, el botón «Cancelar» con confirmación durante el análisis, el doble clic en el resultado y el espaciado nuevo. Se conserva el orden de botones propio de cada sistema (en Windows, el principal a la izquierda); los atajos ⌘ siguen siendo solo de macOS.
- **Asistente:** la tecla Esc ya no cierra ni cancela nada (antes cerraba la aplicación). En macOS se conserva ⌘. y el botón «Cancelar» durante el análisis.
- **Ventana en macOS:** el botón «Quitar» ahora tiene esquinas redondeadas como los demás botones (sigue en naranja). **Reporte HTML:** las marcas de la franja del pipeline (✓, ×, !, –) se dibujan en SVG y quedan centradas en su círculo.
- **Resultado del asistente (todos los sistemas):** «Abrir reporte» ya no cierra la ventana y hay un botón nuevo, «Nuevo análisis», que regresa al inicio para analizar otra ejecución (se conservan `--pom`, `--reports` y `--out-dir` si se pasaron por línea de comandos).
- **Ventana en macOS:** más ancha (760 pt) y de alto base 500 pt; se alarga sola al agregar archivos y vuelve a su alto al quitarlos. El botón «Quitar» es naranja (texto blanco, 5.2:1) para distinguirlo del resto, con foco, Espacio/Enter y estado al pasar el ratón.
- **Ventana en macOS: una sola pantalla** «Nuevo análisis» con el log principal, la comparación, el pom.xml y los reportes (cada fila con sus botones y «Quitar»; «Analizar» se habilita al elegir el log). Alto de ventana estable, título de pantalla sin repetir el nombre de la app, más espacio entre botones, doble clic en el resultado para abrir un archivo y la marca solo en el resultado. En Windows y Linux se mantiene el asistente de 4 pasos.
- **Ventana en macOS, según las guías de Apple** (Windows y Linux no cambian): colores de estado con contraste de 4.5:1 o más en modo claro y oscuro; la descripción queda junto a su título (4 pt) y separada del siguiente bloque (16 pt); el texto se reacomoda al ancho real de la ventana; botones que dicen qué hacen («Elegir log…», «Elegir pom.xml…», «Ahora no») y, en el paso 4, el botón principal es «Agregar archivos…» y Esc omite; el análisis se puede cancelar (botón, Esc, ⌘. o cerrar la ventana) con confirmación, y ⌘W/⌘Q cierran.
- **Ventana del asistente** con la apariencia nativa de cada sistema: macOS (Aqua, modo claro/oscuro del sistema), Windows 11 (Segoe UI Variable) y Windows 10 (Segoe UI), detectados por versión; el orden de los botones sigue la convención de cada uno. Sin franja de color ni icono propio; lo ya elegido se muestra como lista agrupada y la ventana crece si el contenido lo necesita.
- **Reporte HTML** rediseñado: veredicto como encabezado, franja del pipeline (una parada por verificación), índice lateral con indicadores de estado (arriba en móvil), pasos que bloquean marcados con una barra roja, tipografía del sistema, sin encabezados de tabla en mayúsculas y estilos compartidos con el historial (`theme.py`).
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
