# Guía de contribución

¡Gracias por tu interés en mejorar `pipeline-analyzer`! Esta guía resume cómo trabajar en el proyecto.

## Reglas del proyecto

- **Solo biblioteca estándar de Python.** No se agregan dependencias externas.
- **Compatibilidad con Python 3.8:** sin `match`, `X | Y`, `list[str]` en tiempo de ejecución ni `str.removeprefix`.
  Puedes comprobar la sintaxis con `ast.parse(codigo, feature_version=(3, 8))`.
- **Análisis sin red.** El código no puede importar módulos de red, `subprocess` ni `asyncio`; la prueba `NoNetworkTest` lo verifica.
- **Textos para el usuario en español.** Los identificadores del código van en inglés.
- **Las recomendaciones** (título, causa, pasos, comandos) van en `pipeline_analyzer/knowledge.py`, no dentro de `rules.py`.
- **La salida de consola** pasa por `compat.console_safe()`; el avance va a *stderr*.
- **Las pruebas no abren ventanas reales** por defecto: simula `cli.gui_status` o los diálogos y ejecútalas con stdin cerrado. Las pocas pruebas que sí usan tkinter son opcionales y se activan en tu equipo con `PIPELINE_ANALYZER_GUI_TESTS=1` (dependen de la pantalla, el foco y el escalado, por eso no corren en CI).
- **Privacidad:** no incluyas logs, `pom.xml` ni reportes reales en commits, issues ni pull requests. Usa datos sintéticos o sanitizados.

## Entorno de desarrollo

```bash
git clone https://github.com/LensSystems/pipeline-analyzer.git
cd pipeline-analyzer
python3 -m unittest discover -s tests -v < /dev/null
```

En Windows ejecuta `python -m unittest discover -s tests -v`.

## Flujo de ramas

| Rama | Propósito |
|---|---|
| `main` | Código estable. Cada versión publicada se etiqueta aquí (`vX.Y.Z`). Solo recibe cambios desde `develop` o `hotfix/*`. |
| `develop` | Integración del siguiente lanzamiento. Las ramas de trabajo se crean desde aquí y vuelven aquí mediante pull request. |
| `feature/<tema>` | Nueva funcionalidad. |
| `fix/<tema>` | Corrección de errores. |
| `docs/<tema>` | Cambios solo de documentación. |
| `hotfix/<tema>` | Corrección urgente creada desde `main`; se integra en `main` y en `develop`. |

1. Crea tu rama desde `develop`: `git switch develop && git switch -c feature/mi-cambio`.
2. Haz commits pequeños y con sentido; agrega o actualiza las pruebas.
3. Asegúrate de que `python3 -m unittest discover -s tests` pasa.
4. Abre un pull request hacia `develop` describiendo **qué** cambia y **por qué**.

## Mensajes de commit

Se usa [Conventional Commits](https://www.conventionalcommits.org/es/v1.0.0/):

```text
feat: agrega lectura de reportes SARIF
fix: evita duplicar hallazgos de PMD al comparar ejecuciones
docs: aclara el uso de --reports
test: cubre logs de GitLab con secciones anidadas
```

Tipos habituales: `feat`, `fix`, `docs`, `test`, `refactor`, `chore`, `ci`.

## Versionado y lanzamientos

El proyecto sigue el [versionado semántico](https://semver.org/lang/es/). La versión se define solo en
`pipeline_analyzer/__init__.py` (`pyproject.toml` la lee de ahí). Para publicar:

1. Actualiza `CHANGELOG.md` y la versión en `__init__.py` en `develop`.
2. Integra `develop` en `main` mediante pull request.
3. Etiqueta la versión: `git tag -a vX.Y.Z -m "vX.Y.Z"` y súbela con `git push origin vX.Y.Z`.

## Licencia

Al contribuir aceptas que tu aporte se distribuya bajo la licencia [MIT](LICENSE) del proyecto.
