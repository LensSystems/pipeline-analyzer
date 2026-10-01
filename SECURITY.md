# Política de seguridad

## Versiones con soporte

Se corrigen vulnerabilidades en la última versión publicada en la rama `main`.

## Cómo reportar una vulnerabilidad

**No abras un issue público** para reportar una vulnerabilidad.

Usa el reporte privado de GitHub: pestaña **Security → Report a vulnerability** de este repositorio
(<https://github.com/LensSystems/pipeline-analyzer/security/advisories/new>).

Incluye, si puedes:

- una descripción del problema y su impacto;
- los pasos para reproducirlo, con un log o archivo **sintético o sanitizado**;
- la versión de `pipeline-analyzer`, de Python y el sistema operativo.

Responderemos en cuanto sea posible y te mantendremos al tanto de la corrección.

## Qué se considera una vulnerabilidad

- Fuga de secretos hacia los reportes marcados «para compartir» (`reporte.pdf`, `reporte.md`, `reporte.json`).
- Lectura o escritura de archivos fuera de las rutas indicadas por el usuario (p. ej. al procesar un `.zip` manipulado).
- Ejecución de código o conexiones de red inesperadas: el programa **no** debe usar la red.

## Qué no lo es

- Un secreto sin formato conocido que la detección no reconoce: está documentado como limitación.
- Los datos reales que contiene `reporte_completo.*`: es una salida de uso local y está marcada como confidencial.

## Al compartir logs en issues y pull requests

Los logs de CI/CD suelen contener secretos, hosts y nombres internos. **Sanitízalos antes de adjuntarlos** y no publiques reportes
`reporte_completo.*`.
