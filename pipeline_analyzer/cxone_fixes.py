"""Soluciones propuestas para los hallazgos de Checkmarx (SAST y SCA), con ejemplos para Java/Spring/Maven.

Cada solución se elige por nombre de consulta y, si no hay una específica, por CWE. ``assess`` revisa el fragmento de código
de cada resultado y dice si parece un falso positivo (p. ej. la contraseña ya viene de ``${VARIABLE}``) o un problema real
(un valor literal), para decidir qué corregir y qué triar como *Not Exploitable* con justificación.
"""

import re
from typing import Any, Dict, List, Optional, Tuple

_TRIAGE = ("Si tras revisarlo no es explotable: en CxOne cambia el estado a «Not Exploitable» (o «Proposed Not Exploitable») con una "
           "justificación escrita; deja de contar como activo para el breaker.")

FIXES: Dict[str, Dict[str, Any]] = {
    "cleartext_submission_of_sensitive_information": {
        "title": "Cifrar el canal por el que viaja el dato sensible",
        "effort": "medio",
        "steps": [
            "Confirma a dónde se envía el valor (en el reporte: el destino, p. ej. la conexión JDBC que arma el DataSource).",
            "Activa TLS en esa conexión (JDBC: parámetros SSL/truststore del driver; HTTP: https; JMS/ActiveMQ: ssl://).",
            "Guarda el truststore/certificado como Secret y móntalo en el contenedor; no lo incluyas en el repositorio.",
            "Si el cifrado lo da la red (service mesh con mTLS, red privada cifrada) documéntalo y triá el hallazgo como Not Exploitable "
            "con esa evidencia: Checkmarx indica que se puede ignorar si el canal termina en TLS aguas arriba.",
        ],
        "code": "spring.datasource.url=jdbc:informix-sqli://${DB_HOST}:${DB_PORT}/${DB_NAME}:INFORMIXSERVER=${DB_SERVER};ENCRYPT=true\n"
                "# truststore: -Djavax.net.ssl.trustStore=/etc/secrets/truststore.jks -Djavax.net.ssl.trustStorePassword=${TRUSTSTORE_PASSWORD}",
    },
    "use_of_hardcoded_password": {
        "title": "Sacar las contraseñas del código y de los archivos de configuración",
        "effort": "bajo",
        "steps": [
            "Elimina cualquier valor literal (incluso comentado con #) de application*.properties/yml y rota esa credencial: ya quedó en el historial de git.",
            "Inyecta la contraseña desde variables de entorno o un Secret de Kubernetes/OpenShift (${DB_PASSWORD}); no la guardes en un ConfigMap.",
            "Los resultados cuyo valor ya es ${VARIABLE} o @Value(\"${...}\") son falsos positivos por el nombre «password»: triálos como Not Exploitable "
            "con la justificación «valor externalizado en Secret».",
            "Para evitar el ruido repetido, pide al equipo de AppSec ajustar el preset o una regla personalizada que ignore los placeholders ${...}.",
        ],
        "code": "# application.properties\nspring.datasource.password=${INFORMIX_PASSWORD}\n\n# deployment.yaml\nenv:\n  - name: INFORMIX_PASSWORD\n    valueFrom:\n      secretKeyRef: { name: db-credentials, key: password }",
    },
    "stored_absolute_path_traversal": {
        "title": "No construir rutas de disco con datos que pueden venir de almacenamiento",
        "effort": "bajo",
        "steps": [
            "Si el archivo es una plantilla del propio proyecto, léelo del classpath (ClassPathResource / getResourceAsStream) en vez de usar una ruta del disco.",
            "Si la ruta es configurable, valida el nombre contra una lista blanca y verifica que la ruta normalizada quede dentro del directorio permitido.",
            "Acepta datos dinámicos solo para el nombre del archivo, nunca para carpetas.",
        ],
        "code": "Path base = Path.of(templatesDir).toRealPath();\nPath file = base.resolve(templateName).normalize();\nif (!file.startsWith(base)) { throw new IllegalArgumentException(\"Ruta no permitida\"); }\nString template = new String(Files.readAllBytes(file), StandardCharsets.UTF_8);\n"
                "// o, para plantillas empaquetadas:\ntry (InputStream in = new ClassPathResource(\"templates/\" + templateName).getInputStream()) { ... }",
    },
    "information_exposure_through_an_error_message": {
        "title": "No devolver al cliente el detalle de la excepción",
        "effort": "bajo",
        "steps": [
            "Responde con un código de error y un mensaje genérico; no copies ex.getMessage(), el tipo ni el stack trace a la respuesta.",
            "Registra el detalle completo en el log del servidor con un identificador de correlación que también viaje en la respuesta.",
            "Centraliza el manejo en un @ControllerAdvice para que ninguna excepción escape sin tratar.",
        ],
        "code": "log.error(\"Fallo en servicio externo [{}]\", correlationId, ex);\nerrorResponse.setCode(\"DOWNSTREAM_ERROR\");\nerrorResponse.setMessage(\"No fue posible completar la operación\");",
    },
    "heap_inspection": {
        "title": "No dejar contraseñas en memoria como String",
        "effort": "bajo",
        "steps": [
            "Evita guardar la contraseña en un campo de la clase (private String password): léela solo donde se usa (Environment / propiedades del DataSource).",
            "Si debes manejarla en crudo, usa char[]/byte[] y limpia el arreglo con Arrays.fill al terminar.",
            "Es de severidad Low y es una defensa en profundidad: si el equipo acepta el riesgo, triá como Not Exploitable con la justificación.",
        ],
        "code": "@Bean\nDataSource dataSource(DataSourceProperties props) {\n    return props.initializeDataSourceBuilder().build();   // sin copiar la contraseña a un campo propio\n}",
    },
}

CWE_FIXES: Dict[str, Dict[str, Any]] = {
    "89": {"title": "Usar consultas parametrizadas", "effort": "medio", "steps": ["Reemplaza la concatenación de SQL por PreparedStatement / parámetros nombrados (JPA, JdbcTemplate).",
                                                                                  "Valida con lista blanca los nombres dinámicos de columna u ORDER BY."],
           "code": "jdbc.query(\"SELECT * FROM t WHERE id = ?\", mapper, id);"},
    "79": {"title": "Codificar la salida según el contexto", "effort": "medio", "steps": ["Usa el escapado del motor de plantillas (Thymeleaf th:text) y no insertes HTML con datos del usuario.",
                                                                                         "Agrega Content-Security-Policy y valida la entrada."]},
    "22": {"title": "Validar y normalizar rutas de archivo", "effort": "bajo", "steps": ["Normaliza la ruta, verifica que quede dentro del directorio base y usa solo el nombre del archivo."]},
    "78": {"title": "No construir comandos del sistema con datos externos", "effort": "medio", "steps": ["Evita Runtime.exec/ProcessBuilder con entrada del usuario; si es inevitable, usa una lista blanca y argumentos separados."]},
    "117": {"title": "Sanear lo que se escribe en el log", "effort": "bajo", "steps": ["Elimina saltos de línea (\\r\\n) de los valores externos antes de registrarlos o usa un encoder de logs."]},
    "327": {"title": "Usar algoritmos criptográficos vigentes", "effort": "medio", "steps": ["Reemplaza MD5/SHA-1/DES por AES-GCM, SHA-256+ o bcrypt/argon2 para contraseñas."]},
    "611": {"title": "Deshabilitar entidades externas XML", "effort": "bajo", "steps": ["Activa XMLConstants.FEATURE_SECURE_PROCESSING y desactiva DTD y entidades externas en el parser."]},
    "502": {"title": "No deserializar datos no confiables", "effort": "alto", "steps": ["Evita ObjectInputStream con entrada externa; usa JSON con tipos explícitos y una lista blanca de clases."]},
    "918": {"title": "Restringir los destinos de las peticiones salientes", "effort": "medio", "steps": ["Valida la URL contra una lista blanca de hosts y bloquea rangos internos/metadata."]},
    "330": {"title": "Usar un generador aleatorio seguro", "effort": "bajo", "steps": ["Sustituye java.util.Random por SecureRandom para tokens y secretos."]},
    "295": {"title": "Validar certificados TLS", "effort": "bajo", "steps": ["Quita TrustManager/HostnameVerifier permisivos y usa el truststore del sistema o uno explícito."]},
}

_LITERAL_PWD = re.compile(r"(?i)pass(?:word|wd)?\s*[=:]\s*[\"']?(?!\$\{|<|#|\s*$)([^\s\"'$]{3,})")
_PLACEHOLDER = re.compile(r"\$\{[^}]+\}")


def fix_for(rule: str, cwe: str = "") -> Optional[Dict[str, Any]]:
    cwe = re.sub(r"\D", "", str(cwe or ""))
    return FIXES.get(rule.lower()) or CWE_FIXES.get(cwe)


def assess(item: Dict[str, Any]) -> Tuple[str, str]:
    """(veredicto, motivo) de un resultado SAST: ``falso_positivo``, ``real`` o ``revisar``. Se basa en el fragmento de código."""
    rule = (item.get("rule") or "").lower()
    snip = item.get("snippet") or ""
    code = " ".join(snip.split("\n")[:1])
    code = re.sub(r"^\d+\s+", "", code)
    if rule == "use_of_hardcoded_password":
        commented = code.lstrip().startswith(("#", "//"))
        if _PLACEHOLDER.search(code) or "@Value(" in code:
            return "falso_positivo", "la contraseña viene de una variable (${...}), no está escrita en el código"
        if re.search(r"=\s*<(?:SECRET|TOKEN|PASS)\w*>", code):  # valor enmascarado por el sanitizador = había un literal
            return "real", "valor literal de contraseña%s: elimínalo y rota la credencial" % (" (comentado, pero sigue en el repositorio)" if commented else "")
        m = _LITERAL_PWD.search(code)
        if m and not re.fullmatch(r"(?i)(password|passwd|pwd|secret|string|char\[\])[;,)]*", m.group(1)):
            return "real", "valor literal de contraseña%s: elimínalo y rota la credencial" % (" (comentado, pero sigue en el repositorio)" if commented else "")
        if re.search(r"(?i)private\s+(?:final\s+)?String\s+\w*pass", code) or ".password(" in code:
            return "revisar", "solo declara o pasa la variable; confirma que su valor se inyecta desde un Secret"
        return "revisar", "confirma de dónde sale el valor"
    if rule == "cleartext_submission_of_sensitive_information":
        return "revisar", "confirma si la conexión usa TLS; si lo cifra la red/proxy, triá como Not Exploitable"
    if rule == "heap_inspection":
        return "revisar", "defensa en profundidad (Low); corregir o aceptar el riesgo con justificación"
    return "revisar", ""


def sca_fix(item: Dict[str, Any]) -> Dict[str, Any]:
    pkg, ver, fix = item.get("package") or "", item.get("version") or "", item.get("fix_version") or ""
    name = pkg.split(":")[-1] if ":" in pkg else pkg
    group = pkg.split(":")[0].replace("Maven-", "") if ":" in pkg else ""
    steps = ["Actualiza %s de %s a %s%s." % (name or pkg, ver or "?", fix or "la versión corregida", " (o a la última de tu línea mayor)" if fix else "")]
    prop = "tomcat.version" if "tomcat" in pkg.lower() else None
    if prop:
        steps.append("Tomcat lo gestiona el BOM de Spring Boot: sobrescribe la propiedad %s en el pom (o sube la versión de spring-boot-starter-parent)." % prop)
        code = "<properties>\n  <%s>%s</%s>\n</properties>" % (prop, fix or "X.Y.Z", prop)
    else:
        steps.append("Si es una dependencia transitiva, fija la versión en <dependencyManagement>; evita fijar las que ya gestiona el BOM de Spring Boot.")
        code = "<dependencyManagement>\n  <dependencies>\n    <dependency>\n      <groupId>%s</groupId>\n      <artifactId>%s</artifactId>\n      <version>%s</version>\n    </dependency>\n  </dependencies>\n</dependencyManagement>" % (group or "GROUP", name or "ARTIFACT", fix or "X.Y.Z")
    steps.append("Verifica con: mvn dependency:tree -Dincludes=%s y vuelve a escanear." % (pkg.replace("Maven-", "") if ":" in pkg else name))
    return {"title": "Actualizar %s%s" % (name or pkg, " a %s" % fix if fix else ""), "effort": "bajo", "steps": steps, "code": code}


def triage_hint() -> str:
    return _TRIAGE
