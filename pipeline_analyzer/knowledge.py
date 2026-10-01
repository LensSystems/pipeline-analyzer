"""Base de conocimiento: explicación, pasos de remediación y snippets por tipo de hallazgo.

Las claves coinciden con ``Finding.id`` (o ``SONAR:<metricKey>`` para condiciones del quality gate).
Los campos ``title`` y ``why`` se formatean con ``str.format_map`` usando los parámetros del
hallazgo; ``steps``, ``snippet`` y ``commands`` se muestran tal cual.
"""

from typing import Any, Dict

SNIPPET_PLUGIN_MANAGEMENT = """<build>
  <pluginManagement>
    <plugins>
      <plugin>
        <groupId>com.github.spotbugs</groupId>
        <artifactId>spotbugs-maven-plugin</artifactId>
        <version>4.9.8.1</version>
        <dependencies>
          <!-- Fuerza un core de SpotBugs con ASM compatible con Java 25 -->
          <dependency>
            <groupId>com.github.spotbugs</groupId>
            <artifactId>spotbugs</artifactId>
            <version>4.9.8</version>
          </dependency>
        </dependencies>
        <configuration>
          <effort>Max</effort>
          <threshold>Low</threshold>
          <excludeFilterFile>findbugsfilter.xml</excludeFilterFile>
        </configuration>
      </plugin>
      <plugin>
        <groupId>org.apache.maven.plugins</groupId>
        <artifactId>maven-pmd-plugin</artifactId>
        <version>3.28.0</version>
      </plugin>
      <plugin>
        <groupId>org.apache.maven.plugins</groupId>
        <artifactId>maven-checkstyle-plugin</artifactId>
        <version>3.6.0</version>
      </plugin>
    </plugins>
  </pluginManagement>
</build>"""

SNIPPET_DOCKER_NAME = """# pipeline-templates: nombre de contenedor único por intento
- bash: |
    NAME="$(Build.BuildId)-$(System.JobAttempt)-$(System.JobId)"
    docker rm -f "$NAME" 2>/dev/null || true
    docker run -d --name "$NAME" ...
# y al final del job:
- bash: docker rm -f "$(Build.BuildId)-$(System.JobAttempt)-$(System.JobId)" || true
  condition: always()"""

SNIPPET_SONAR_WAIT = """mvn sonar:sonar \\
  -Dsonar.qualitygate.wait=true \\
  -Dsonar.qualitygate.timeout=300"""

SNIPPET_S2095 = """// Antes: el recurso queda abierto si ocurre una excepción
ZipOutputStream zos = new ZipOutputStream(baos);
...
zos.close();

// Después: try-with-resources
try (ZipOutputStream zos = new ZipOutputStream(baos)) {
    ...
}
return baos.toByteArray();   // leer DESPUÉS de cerrar el zip"""

SNIPPET_EMPTY_ARRAY_TEST = """// El código ahora retorna un arreglo vacío en lugar de null
byte[] result = service.metodo(...);
assertNotNull(result);
assertEquals(0, result.length);      // o assertArrayEquals(new byte[0], result)"""

SNIPPET_EMPTY_STRING_TEST = """// El código ahora retorna "" en lugar de null
assertEquals("", resultado);         // o assertTrue(resultado.isEmpty())"""

SNIPPET_SUREFIRE = """<plugin>
  <groupId>org.apache.maven.plugins</groupId>
  <artifactId>maven-surefire-plugin</artifactId>
  <configuration>
    <testFailureIgnore>false</testFailureIgnore>
  </configuration>
</plugin>"""

SNIPPET_LOGBACK_TEST = """<!-- src/test/resources/logback-test.xml -->
<configuration>
  <appender name="CONSOLE" class="ch.qos.logback.core.ConsoleAppender">
    <encoder><pattern>%d{HH:mm:ss} %-5level %logger{36} - %msg%n</pattern></encoder>
  </appender>
  <logger name="com.tuempresa" level="WARN"/>
  <root level="WARN"><appender-ref ref="CONSOLE"/></root>
</configuration>"""

SNIPPET_MOCKITO_AGENT = """<plugin>
  <groupId>org.apache.maven.plugins</groupId>
  <artifactId>maven-dependency-plugin</artifactId>
  <executions>
    <execution><goals><goal>properties</goal></goals></execution>
  </executions>
</plugin>
<plugin>
  <groupId>org.apache.maven.plugins</groupId>
  <artifactId>maven-surefire-plugin</artifactId>
  <configuration>
    <!-- @{argLine} conserva el agente de JaCoCo -->
    <argLine>@{argLine} -javaagent:${org.mockito:mockito-core:jar}</argLine>
  </configuration>
</plugin>"""

KB: Dict[str, Dict[str, Any]] = {
    # ------------------------------------------------------------ Tests
    "TESTS_FAILED": {
        "title": "{failures} test(s) unitario(s) fallando",
        "why": "Los tests que fallan indican una regresión o tests desactualizados respecto al código.",
        "steps": [
            "Revisa cada test listado: compara el valor esperado con el obtenido.",
            "Si el cambio de comportamiento es intencional (p. ej. retornar vacío en vez de null), actualiza el test.",
            "Si no es intencional, corrige el código de producción.",
            "Reproduce localmente con: mvn -Dtest=<Clase>#<metodo> test",
        ],
    },
    "TESTS_FAILURE_IGNORED": {
        "title": "El build reporta SUCCESS con tests fallidos",
        "why": "surefire tiene testFailureIgnore=true: las regresiones no rompen el pipeline y pasan desapercibidas.",
        "steps": [
            "Quita <testFailureIgnore>true</testFailureIgnore> del pom (build principal y perfiles).",
            "Si el equipo necesita un periodo de transición, usa -Dmaven.test.failure.ignore solo en ramas de feature.",
        ],
        "snippet": SNIPPET_SUREFIRE,
    },
    "TESTS_RUN_TWICE": {
        "title": "Los tests se ejecutan {executions} veces en el mismo pipeline",
        "why": "El paso de preparación de dependencias para CxOne vuelve a correr la suite completa: tiempo desperdiciado.",
        "steps": [
            "En el paso 'Prepare Maven Dependencies For CxOne' usa -DskipTests o 'mvn dependency:go-offline'.",
        ],
    },
    "TEST_LOG_NOISE": {
        "title": "Salida de tests muy ruidosa ({lines} líneas, {error_logs} logs ERROR)",
        "why": "Los tests escriben logs ERROR y stack traces completos; esto oculta los fallos reales en el log.",
        "steps": [
            "Agrega src/test/resources/logback-test.xml con nivel WARN para tus paquetes.",
            "En tests de manejo de errores, verifica el log con un appender de prueba en vez de imprimirlo.",
        ],
        "snippet": SNIPPET_LOGBACK_TEST,
    },
    "MOCKITO_SELF_ATTACH": {
        "title": "Mockito se auto-adjunta como agente (dejará de funcionar en JDK futuros)",
        "why": "JDK 21+ advierte sobre la carga dinámica de agentes; en versiones futuras estará deshabilitada por defecto.",
        "steps": ["Configura Mockito como -javaagent en el argLine de surefire (combinado con @{argLine} de JaCoCo)."],
        "snippet": SNIPPET_MOCKITO_AGENT,
    },
    # ------------------------------------------------------------ Sonar
    "SONAR_STALE_GATE": {
        "title": "El quality gate reportado no corresponde a esta ejecución",
        "why": (
            "Esta corrida tuvo {passed}/{total} tests OK ({expected}%), pero Sonar reporta "
            "test_success_density={reported}%. El reporte se consultó {delay}s después de subir el análisis, "
            "antes de que el Compute Engine lo procesara: se está leyendo el análisis ANTERIOR."
        ),
        "steps": [
            "Agrega -Dsonar.qualitygate.wait=true al paso 'Sonarqube - Run' del template.",
            "Alternativa: consultar api/ce/task?id=<ceTaskId> (target/sonar/report-task.txt) hasta SUCCESS y leer el gate por analysisId.",
            "Mientras tanto, valida el resultado real en la UI de SonarQube.",
        ],
        "snippet": SNIPPET_SONAR_WAIT,
    },
    "SONAR_RACE": {
        "title": "Posible lectura prematura del quality gate ({delay}s tras subir el análisis)",
        "why": "El paso 'Get report' no espera al Compute Engine; el gate mostrado puede ser del análisis previo.",
        "steps": ["Agrega -Dsonar.qualitygate.wait=true en el template y confirma el resultado en la UI."],
        "snippet": SNIPPET_SONAR_WAIT,
    },
    "SONAR:reliability_rating": {
        "title": "Sonar reliability_rating = {letter} (umbral: A) en el código general",
        "why": (
            "La nota de confiabilidad se basa en el peor Bug abierto: B=Minor, C=Major, D=Critical, E=Blocker. "
            "El gate exige A: cero bugs de cualquier severidad."
        ),
        "steps": [
            "Lista los bugs: Issues → Type=Bug → Status=Open (o la API de abajo).",
            "La causa más común en servicios de PDF/ZIP es java:S2095 (recursos sin cerrar): usa try-with-resources.",
            "Usa SonarQube for IDE (VS Code), en Standalone o Connected Mode, para ubicarlos en el editor.",
            "Si es falso positivo, márcalo en SonarQube con justificación.",
        ],
        "commands": [
            'curl -s -u "$SONAR_TOKEN:" "$SONAR_HOST/api/issues/search?componentKeys=$PROJECT_KEY&types=BUG&resolved=false&ps=100" | jq \'.issues[] | {severity, rule, component, line, message}\'',
        ],
        "snippet": SNIPPET_S2095,
    },
    "SONAR:new_reliability_rating": {
        "title": "Sonar new_reliability_rating = {letter} en código nuevo",
        "why": "Se introdujeron bugs en el código nuevo del periodo actual.",
        "steps": ["Filtra Issues → New Code → Type=Bug y corrígelos antes de fusionar."],
        "snippet": SNIPPET_S2095,
    },
    "SONAR:security_rating": {
        "title": "Sonar security_rating = {letter}",
        "why": "Hay vulnerabilidades abiertas en el código.",
        "steps": ["Issues → Type=Vulnerability; corrígelas y revisa los Security Hotspots."],
    },
    "SONAR:new_security_rating": {
        "title": "Sonar new_security_rating = {letter} en código nuevo",
        "why": "Se introdujeron vulnerabilidades en el código nuevo.",
        "steps": ["Issues → New Code → Type=Vulnerability."],
    },
    "SONAR:sqale_rating": {
        "title": "Sonar maintainability rating = {letter}",
        "why": "La deuda técnica (code smells) supera el umbral.",
        "steps": ["Issues → Type=Code Smell ordenados por esfuerzo; atiende primero Blocker/Critical."],
    },
    "SONAR:new_maintainability_rating": {
        "title": "Sonar new_maintainability_rating = {letter}",
        "why": "El código nuevo introduce demasiada deuda técnica.",
        "steps": ["Issues → New Code → Type=Code Smell."],
    },
    "SONAR:coverage": {
        "title": "Cobertura general {actual}% < {threshold}%",
        "why": "La cobertura total no alcanza el umbral del quality gate.",
        "steps": [
            "Revisa en Sonar → Measures → Coverage las clases con menor cobertura.",
            "Agrega tests a lógica de negocio (business/service/util); DTOs y config suelen estar excluidos.",
            "Verifica que Sonar lea el XML de JaCoCo: sonar.coverage.jacoco.xmlReportPaths=target/site/jacoco/jacoco.xml",
        ],
    },
    "SONAR:new_coverage": {
        "title": "Cobertura de código nuevo {actual}% < {threshold}%",
        "why": "El código modificado en el periodo no tiene suficientes tests.",
        "steps": ["Sonar → New Code → Coverage: agrega tests a las líneas nuevas sin cubrir."],
    },
    "SONAR:test_success_density": {
        "title": "Éxito de tests en Sonar {actual}% < {threshold}%",
        "why": "Sonar leyó reportes surefire con tests fallidos.",
        "steps": [
            "Corrige los tests fallidos.",
            "Si esta corrida no tuvo fallos, el dato es del análisis anterior (ver 'quality gate desfasado').",
        ],
    },
    "SONAR:skipped_tests": {
        "title": "Hay {actual} test(s) omitidos",
        "why": "El gate no permite tests @Disabled/@Ignore.",
        "steps": ["Habilita o elimina los tests omitidos."],
    },
    "SONAR:duplicated_lines_density": {
        "title": "Duplicación {actual}% > {threshold}%",
        "why": "Hay bloques de código duplicados.",
        "steps": ["Sonar → Measures → Duplications; extrae el código repetido a métodos o clases comunes."],
    },
    "SONAR:new_duplicated_lines_density": {
        "title": "Duplicación en código nuevo {actual}% > {threshold}%",
        "why": "El código nuevo tiene bloques duplicados.",
        "steps": ["Refactoriza los bloques duplicados señalados en Sonar."],
    },
    "SONAR_GENERIC": {
        "title": "Condición de Sonar '{metric}' en ERROR ({actual} vs umbral {threshold})",
        "why": "Una condición del quality gate no se cumple.",
        "steps": ["Revisa la métrica en la UI de SonarQube."],
    },
    "SONAR_COVERAGE_MARGIN": {
        "title": "Cobertura {actual}% muy cerca del umbral {threshold}%",
        "why": "Un margen menor a 1 punto hace que cualquier cambio sin tests rompa el gate.",
        "steps": ["Agrega tests a las clases con menor cobertura para ganar margen."],
    },
    "SONAR_BRANCH_ON_PR": {
        "title": "Un PR se analiza como la rama '{branch}' en Sonar",
        "why": "El análisis de PR #{pr} sobrescribe el historial de {branch} y no aprovecha la decoración de PR.",
        "steps": [
            "En builds de PR usa sonar.pullrequest.key, sonar.pullrequest.branch y sonar.pullrequest.base en lugar de sonar.branch.name.",
        ],
    },
    "SONAR_SHALLOW_CLONE": {
        "title": "Clone superficial: Sonar no tiene 'blame'",
        "why": "Sin historial git, Sonar no identifica bien el código nuevo ni asigna autores.",
        "steps": ["En el checkout del pipeline configura fetchDepth: 0."],
    },
    "SONAR_DEPRECATED_PROPS": {
        "title": "Propiedades Sonar obsoletas en uso",
        "why": "sonar.jacoco.reportPath / sonar.dynamicAnalysis ya no se soportan y se ignoran.",
        "steps": [
            "Elimínalas del pom.",
            "Define sonar.coverage.jacoco.xmlReportPaths=${project.build.directory}/site/jacoco/jacoco.xml",
        ],
    },
    "SONAR_PLUGIN_UNPINNED": {
        "title": "sonar-maven-plugin sin versión fija",
        "why": "El análisis puede cambiar sin aviso cuando se publica una versión nueva del plugin.",
        "steps": ["Fija org.sonarsource.scanner.maven:sonar-maven-plugin en pluginManagement o en el template."],
    },
    "SONAR_SCANNER_JDK": {
        "title": "El scanner de Sonar corre con Java {scanner} y el proyecto es Java {project}",
        "why": "Usar un JDK menor al del proyecto puede degradar el análisis semántico (se detectan 'preview features').",
        "steps": [
            "Usa una imagen del scanner con JDK >= {project}.",
            "Valida que SonarQube {server} soporte Java {project}; considera actualizar el servidor.",
        ],
    },
    # ------------------------------------------------------------ CxOne
    "CXONE_SAST": {
        "title": "CxOne SAST: {critical} Critical / {high} High activas",
        "why": "El breaker de seguridad bloquea el pipeline por hallazgos SAST Critical/High.",
        "steps": [
            "Abre el escaneo en CxOne y revisa el query, archivo y línea de cada hallazgo.",
            "En servicios de PDF/ZIP/JDBC suelen ser Path Traversal/Zip Slip, SQL Injection o Log Forging.",
            "Si es real: corrige (valida rutas y nombres de ZipEntry, usa PreparedStatement, sanitiza logs).",
            "Si es falso positivo: márcalo 'Not Exploitable' con justificación (hoy cuenta como activo).",
        ],
    },
    "CXONE_SAST_TO_VERIFY": {
        "title": "{count} hallazgo(s) SAST en estado TO_VERIFY",
        "why": "Los hallazgos sin triaje cuentan como activos para el breaker.",
        "steps": ["Tríalos en CxOne: Confirmed, Not Exploitable o Proposed Not Exploitable."],
    },
    "CXONE_NO_BASELINE": {
        "title": "CxOne sin línea base en main/master",
        "why": "Sin línea base, el breaker evalúa todo el código (no solo lo nuevo) y bloquea por deuda histórica.",
        "steps": ["Ejecuta un escaneo CxOne sobre master/main para crear la línea base."],
    },
    "CXONE_SCA_HIGH": {
        "title": "CxOne SCA: {critical} Critical / {high} High en dependencias",
        "why": "Hay dependencias con vulnerabilidades conocidas (hoy {status} por política).",
        "steps": [
            "Abre el reporte SCA y ubica el paquete y la versión corregida de cada CVE.",
            "Actualiza la dependencia directa o fuerza la transitiva en <dependencyManagement>.",
            "Evita fijar versiones que el BOM de Spring Boot ya gestiona.",
        ],
        "commands": ["mvn dependency:tree -Dincludes=<groupId>:<artifactId>"],
    },
    "CXONE_SCS_PARTIAL": {
        "title": "CxOne Supply Chain / Secret Detection con estado Partial",
        "why": "El análisis de supply chain no se completó; los resultados pueden estar incompletos.",
        "steps": ["Revisa en CxOne el motivo del estado Partial (permisos del repo, configuración de SCS)."],
    },
    # ------------------------------------------------------------ TMAS
    "TMAS_VULNS": {
        "title": "TMAS: {critical} Critical / {high} High en el artefacto",
        "why": "El escaneo del JAR/imagen encontró vulnerabilidades.",
        "steps": ["Revisa el JSON de TMAS y actualiza las librerías afectadas."],
    },
    # ------------------------------------------------------------ Análisis estático
    "STATIC_NOT_EXECUTED": {
        "title": "No se ejecutaron: {tools}",
        "why": "Los pasos ReportBugs fallaron antes de correr Maven; los breakers fallan por falta de reporte, no por el código.",
        "steps": [
            "Revisa el hallazgo de infraestructura (conflicto de contenedor Docker) y relanza el pipeline.",
            "No interpretes estos breakers como violaciones de código hasta que se ejecuten.",
        ],
    },
    "DOCKER_CONTAINER_CONFLICT": {
        "title": "Contenedor Docker huérfano en el agente: {containers}",
        "why": (
            "El template nombra el contenedor con Build.BuildNumber; un contenedor anterior con el mismo nombre "
            "impide crearlo y los 'docker exec' siguientes fallan (OCI runtime exec failed)."
        ),
        "steps": [
            "Inmediato: pide a plataforma eliminar el contenedor (docker rm -f <nombre>) y relanza.",
            "De fondo (PR a pipeline-templates): nombre único con Build.BuildId + System.JobAttempt y limpieza con condition: always().",
        ],
        "commands": [
            'az vm run-command invoke -g <RG> -n <VM_AGENTE> --command-id RunShellScript --scripts "docker ps -a --filter name={first}"',
        ],
        "snippet": SNIPPET_DOCKER_NAME,
    },
    "SPOTBUGS_JAVA_UNSUPPORTED": {
        "title": "SpotBugs {plugin} no soporta Java {java} (class file major {major})",
        "why": (
            "El ASM incluido en esa versión de SpotBugs no lee clases de Java {java}; no analiza nada "
            "(NoClassesFoundToAnalyzeException) y el breaker falla por falta de reporte."
        ),
        "steps": [
            "Declara spotbugs-maven-plugin en <build><pluginManagement> (no solo en un perfil) con una versión compatible.",
            "Si el template fija la versión en la línea de comandos, fuerza el core 'com.github.spotbugs:spotbugs' vía <dependencies> del plugin.",
            "Si aun así falla, abre un PR a pipeline-templates para actualizar la versión.",
            "Valida localmente con la misma invocación del template.",
        ],
        "commands": ["mvn -B clean compile com.github.spotbugs:spotbugs-maven-plugin:{plugin}:spotbugs"],
        "snippet": SNIPPET_PLUGIN_MANAGEMENT,
    },
    "PMD_VIOLATIONS": {
        "title": "PMD: {count} violación(es)",
        "why": "El breaker de PMD no tolera violaciones.",
        "steps": [
            "Ejecuta localmente para ver el detalle de cada regla.",
            "El XML completo también se publica en el repositorio de análisis del pipeline.",
        ],
        "commands": ["mvn pmd:check -Dpmd.printFailingErrors=true"],
    },
    "CHECKSTYLE_VIOLATIONS": {
        "title": "Checkstyle: {count} violación(es)",
        "why": "El breaker de Checkstyle no tolera violaciones.",
        "steps": ["Ejecuta localmente y corrige según google_checks.xml."],
        "commands": ["mvn checkstyle:check -Dcheckstyle.consoleOutput=true"],
    },
    "STATIC_TOOL_FAILED": {
        "title": "{tool} terminó con error de ejecución",
        "why": "La herramienta falló al ejecutarse y no generó reporte.",
        "steps": ["Revisa el paso ReportBugs de {tool} en el log (línea {line})."],
    },
    # ------------------------------------------------------------ Otros
    "SMTP_AUTH": {
        "title": "Falla el envío de correo del pipeline (SMTP EAUTH 535)",
        "why": "La credencial SMTP del mailer está vencida o requiere un App Password.",
        "steps": ["Pide al equipo de plataforma renovar el secreto del mailer en el Library/Key Vault."],
    },
    "STEP_FAILED_OTHER": {
        "title": "Paso '{step}' falló",
        "why": "Error reportado: {error}",
        "steps": ["Revisa el paso en el log (línea {line})."],
    },
    # ------------------------------------------------------------ POM
    "POM_TEST_FAILURE_IGNORE": {
        "title": "pom.xml: testFailureIgnore=true ({count} ocurrencia(s))",
        "why": "Los tests fallidos no rompen el build.",
        "steps": ["Elimínalo o ponlo en false."],
        "snippet": SNIPPET_SUREFIRE,
    },
    "POM_PLUGINS_ONLY_IN_PROFILE": {
        "title": "pom.xml: {plugins} solo están configurados dentro de perfiles",
        "why": "El pipeline no activa esos perfiles; Maven usa otra versión o la del template (p. ej. SpotBugs viejo).",
        "steps": ["Muévelos a <build><pluginManagement> con versión fija."],
        "snippet": SNIPPET_PLUGIN_MANAGEMENT,
    },
    "POM_DUPLICATE_PROPERTY": {
        "title": "pom.xml: propiedad duplicada '{prop}' ({count} veces)",
        "why": "Maven solo toma el último valor ({last}); los anteriores se ignoran.",
        "steps": ["Deja una sola propiedad con los valores separados por coma."],
    },
    "POM_DEPRECATED_SONAR": {
        "title": "pom.xml: propiedades Sonar obsoletas: {props}",
        "why": "Sonar las ignora.",
        "steps": ["Elimínalas y usa sonar.coverage.jacoco.xmlReportPaths."],
    },
    "POM_JACOCO_ZERO": {
        "title": "pom.xml: la regla de jacoco:check tiene mínimo 0",
        "why": "Es un gate que nunca falla.",
        "steps": ["Define un umbral real, p. ej. <minimum>0.80</minimum> sobre LINE."],
    },
    "POM_SPOTBUGS_THRESHOLD": {
        "title": "pom.xml: SpotBugs threshold inválido '{value}'",
        "why": "Los valores válidos son High, Default, Medium, Low e Ignore.",
        "steps": ["Usa <threshold>Low</threshold> o <threshold>Medium</threshold>."],
    },
    "POM_SKIPEXEC": {
        "title": "pom.xml: parámetro obsoleto skipExec",
        "why": "Maven lo marca como deprecated.",
        "steps": ["Elimínalo; usa skipTests si hace falta."],
    },
    "POM_UNDEFINED_PROPERTY": {
        "title": "pom.xml: propiedades usadas pero no definidas: {props}",
        "why": "Se resuelven como texto literal y pueden filtrar tests o rutas sin querer.",
        "steps": ["Defínelas en <properties> o elimina las referencias."],
    },
    "POM_UNUSED_VERSION_PROPERTY": {
        "title": "pom.xml: propiedades de versión sin uso: {props}",
        "why": "Confunden sobre la versión real en uso.",
        "steps": ["Úsalas en las dependencias o plugins correspondientes, o elimínalas."],
    },
    "POM_JACKSON_MIX": {
        "title": "pom.xml: Jackson 2 (com.fasterxml) y Jackson 3 (tools.jackson) declarados juntos",
        "why": "Spring Boot 4 usa Jackson 3; tener ambos duplica el classpath y la superficie para SCA.",
        "steps": ["Elimina Jackson 2 salvo que una librería lo requiera; deja que el BOM gestione Jackson 3."],
    },
    "POM_VERSION_MISMATCH": {
        "title": "pom.xml: versiones desalineadas en {group}: {versions}",
        "why": "Artefactos del mismo grupo con versiones distintas pueden provocar NoSuchMethodError en runtime.",
        "steps": ["Quita las versiones explícitas y deja que el BOM las alinee."],
    },
    "POM_JAVAX_WITH_JAKARTA": {
        "title": "pom.xml: dependencias javax.* con Spring Boot {boot}",
        "why": "Spring Boot 3+ usa Jakarta EE; javax.* no es compatible: {deps}",
        "steps": ["Elimínalas o reemplázalas por su equivalente jakarta.*."],
    },
    "POM_LOMBOK_SCOPE": {
        "title": "pom.xml: lombok sin scope provided",
        "why": "Lombok se empaqueta dentro del JAR sin necesidad.",
        "steps": ["Agrega <scope>provided</scope> u <optional>true</optional>."],
    },
    "POM_JUNIT4_LEFTOVERS": {
        "title": "pom.xml: restos de JUnit 4: {deps}",
        "why": "El proyecto usa JUnit 5; el listener de JUnit 4 y estas dependencias no aportan nada.",
        "steps": ["Elimínalas junto con la propiedad 'listener' de surefire."],
    },
    "POM_REDUNDANT_VALIDATION": {
        "title": "pom.xml: validación declarada a mano junto con spring-boot-starter-validation: {deps}",
        "why": "El starter ya las trae en versiones compatibles; declararlas a mano puede generar conflictos.",
        "steps": ["Elimínalas."],
    },
    "POM_BOM_OVERRIDES": {
        "title": "pom.xml: {count} dependencia(s) con versión fija que el BOM de Spring Boot ya gestiona",
        "why": "Pisar el BOM desalinea versiones e impide recibir parches de seguridad al actualizar Spring Boot: {deps}",
        "steps": ["Quita <version> de esas dependencias (salvo overrides de CVE documentados)."],
    },
    "POM_OUTDATED_DEP": {
        "title": "pom.xml: {dep} {version} desactualizada",
        "why": "{reason}",
        "steps": ["Actualiza a {target} o superior y valida con el reporte SCA."],
    },
    "POM_MILESTONE_PLUGIN": {
        "title": "pom.xml: plugin en versión milestone: {plugins}",
        "why": "Las versiones -M son preliminares.",
        "steps": ["Actualiza a una versión estable."],
    },
}


SNIPPET_SECURITY_CONTEXT = """spec:
  template:
    spec:
      securityContext:
        runAsNonRoot: true
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: mi-app
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true      # monta un emptyDir en /tmp si la app escribe ahí
            capabilities:
              drop: ["ALL"]"""

SNIPPET_JOLOKIA_OFF = """# Imágenes Red Hat OpenJDK (ubi9/openjdk-*): desactivar el agente Jolokia
env:
  - name: AB_JOLOKIA_OFF
    value: "true"
# y eliminar el containerPort 8778 (jolokia) del Deployment"""

SNIPPET_SECRET_REF = """# ConfigMap: solo referencias
spring.datasource.password=${DB_PASSWORD}

# Deployment: el valor real viene de un Secret
envFrom:
  - secretRef:
      name: mi-app-db-credentials"""

SNIPPET_PIN_IMAGE = """# En vez de :latest, fija por digest (inmutable)
image: registry.example.com/ubi9/openjdk-25@sha256:<digest>
# obtener el digest:
#   skopeo inspect docker://registry.example.com/ubi9/openjdk-25:latest | jq -r .Digest"""

SNIPPET_VERIFY_DOWNLOAD = """curl -fsSLO https://proveedor/herramienta.tar.gz
echo "<sha256-publicado>  herramienta.tar.gz" | sha256sum -c -
tar xzf herramienta.tar.gz"""

SNIPPET_PIN_TEMPLATE = """# azure-pipelines.yml: referenciar templates por tag o commit, no por rama
resources:
  repositories:
    - repository: templates
      type: git
      name: Proyecto/pipeline-templates
      ref: refs/tags/v1.4.2"""

SNIPPET_ACTUATOR = """management.endpoints.web.exposure.include=health,info
management.endpoint.health.show-details=never
management.endpoint.shutdown.enabled=false
management.server.port=8081   # puerto de gestión no expuesto por el Service/Route"""

KB.update({
    # ------------------------------------------------------------ Seguridad del pipeline
    "SEC_SECRETS_IN_LOG": {
        "title": "{count} posible(s) secreto(s) en claro en el log del pipeline",
        "why": ("Azure DevOps solo enmascara las variables marcadas como secretas; todo lo demás queda en el log, "
                "visible para cualquiera con acceso al pipeline y en sus retenciones."),
        "steps": [
            "Revisa cada línea indicada en el log ORIGINAL (el reporte muestra el valor enmascarado).",
            "Si es un secreto real: rótalo YA (considéralo comprometido) y elimina o restringe el log.",
            "Mueve el valor a una variable secreta, un Variable Group ligado a Key Vault o una secure file.",
            "Evita 'set -x', 'env' o 'cat' de archivos de configuración en los scripts del pipeline.",
        ],
    },
    "SEC_SANITIZER_MARKERS": {
        "title": "El log original contenía {count} valor(es) sensible(s) (marcados por el sanitizador)",
        "why": ("El sanitizador reemplazó esos valores con marcadores como <SECRET_n> o <TOKEN_n>. Algunos pueden ser falsos "
                "positivos (números de línea, IDs), pero los reales significan que el pipeline imprime datos sensibles."),
        "steps": [
            "Revisa el contexto de cada marcador en la evidencia y ubícalo en el log original.",
            "Para los reales: corrige el script que los imprime y rota la credencial si aplica.",
        ],
    },
    "SEC_INSECURE_HTTP": {
        "title": "Conexiones sin TLS (http://) en el pipeline",
        "why": "Descargar dependencias o herramientas por http permite manipulación en tránsito (MITM).",
        "steps": ["Cambia las URLs a https:// (Maven 3.8.1+ bloquea repositorios http por defecto por esta razón)."],
    },
    "SEC_TLS_DISABLED": {
        "title": "Verificación TLS deshabilitada en el pipeline",
        "why": "Opciones como curl -k o maven.wagon.http.ssl.insecure aceptan cualquier certificado: MITM trivial.",
        "steps": [
            "Elimina la opción insegura.",
            "Si el problema es una CA corporativa, agrégala al truststore del agente o de la imagen, no desactives la validación.",
        ],
    },
    "SEC_PIPE_TO_SHELL": {
        "title": "Scripts remotos ejecutados con curl|bash",
        "why": "Se ejecuta código remoto sin revisión ni verificación de integridad; quien controle la URL controla el agente.",
        "steps": ["Descarga el script, verifica su checksum o firma, y versiónalo en el repositorio de templates."],
        "snippet": SNIPPET_VERIFY_DOWNLOAD,
    },
    "SEC_LATEST_IMAGES": {
        "title": "Imágenes de build/escaneo con tag mutable: {images}",
        "why": "':latest' cambia sin aviso: builds no reproducibles y riesgo de ejecutar una imagen alterada.",
        "steps": ["Fija las imágenes por digest (@sha256) o por un tag de versión inmutable y actualízalas de forma controlada."],
        "snippet": SNIPPET_PIN_IMAGE,
    },
    "SEC_MUTABLE_REPOS": {
        "title": "Templates y listas de excepciones clonados de ramas mutables: {repos}",
        "why": ("Un cambio en esas ramas altera el pipeline de todos los proyectos sin revisión por proyecto; en la lista de "
                "vulnerabilidades conocidas, podría silenciar hallazgos de TMAS."),
        "steps": [
            "Referencia pipeline-templates por tag o commit.",
            "Protege las ramas con PR obligatorio y revisores.",
            "Audita los cambios en known-vulnerabilities (excepciones de seguridad).",
        ],
        "snippet": SNIPPET_PIN_TEMPLATE,
    },
    "SEC_UNVERIFIED_DOWNLOADS": {
        "title": "Herramientas descargadas sin verificar su integridad: {steps}",
        "why": "Si el origen o el proxy se comprometen, el agente ejecuta un binario alterado con acceso a secretos del pipeline.",
        "steps": ["Verifica el checksum SHA-256 o la firma publicada por el proveedor antes de ejecutar la herramienta."],
        "snippet": SNIPPET_VERIFY_DOWNLOAD,
    },
    "SEC_VULNERABLE_DEPS": {
        "title": "{count} dependencia(s) con CVE conocidos en el log",
        "why": "Versiones con vulnerabilidades públicas explotables.",
        "steps": [
            "Actualiza a la versión corregida indicada (o superior) o fuerza la transitiva en <dependencyManagement>.",
            "Si viene de una herramienta del build (no de la app), actualiza la imagen del agente.",
            "Confirma con el reporte SCA de CxOne.",
        ],
        "commands": ["mvn dependency:tree -Dincludes=:<artifactId>"],
    },
    "SEC_CONTAINER_ISOLATION": {
        "title": "Alertas de aislamiento de contenedores en el agente",
        "why": ("'possible container breakout detected' es la protección de runc contra CVE-2024-21626 (Leaky Vessels): "
                "se intentó un exec con un directorio de trabajo fuera del contenedor, normalmente por un contenedor huérfano. "
                "--privileged o montar docker.sock dan al build control total del host."),
        "steps": [
            "Verifica que el agente tenga runc >= 1.1.12 y Docker/containerd actualizados.",
            "Elimina contenedores huérfanos y usa nombres únicos por build (ver hallazgo de Docker).",
            "Evita --privileged y montar /var/run/docker.sock; considera agentes efímeros.",
        ],
        "commands": ["runc --version && docker version --format '{{.Server.Version}}'"],
    },
    "SEC_SONAR_UNSUPPORTED": {
        "title": "SonarQube {version} fuera de soporte",
        "why": "Las versiones anteriores a la LTA vigente (2025.x) ya no reciben parches de seguridad ni reglas para Java recientes.",
        "steps": ["Planea actualizar el servidor a la LTA vigente (SonarQube Server 2025.x)."],
    },
    "SEC_SCORECARD_SKIPPED": {
        "title": "CxOne Scorecard (SCS) no se ejecutó",
        "why": "Falta configuración (--scs-repo-url / --scs-repo-token); la evaluación de supply chain del repo queda incompleta.",
        "steps": ["Agrega los argumentos de SCS al paso de CxOne con un token de solo lectura guardado como variable secreta."],
    },
    "SEC_REPORTS_DISTRIBUTED": {
        "title": "Reportes de vulnerabilidades distribuidos por {channels}",
        "why": "Los reportes describen debilidades explotables; su audiencia debería ser mínima.",
        "steps": [
            "Restringe el acceso al repositorio de análisis y a la lista de distribución.",
            "Evita adjuntar detalles de SAST/SCA en correos; enlaza a la plataforma con control de acceso.",
        ],
    },
    # ------------------------------------------------------------ Kubernetes / OpenShift
    "K8S_SECURITY_CONTEXT": {
        "title": "Deployment sin securityContext endurecido ({missing})",
        "why": "Sin estas restricciones, un RCE en la app obtiene más privilegios dentro del contenedor y más superficie para escapar.",
        "steps": ["Agrega securityContext a nivel pod y contenedor (compatible con la SCC restricted-v2 de OpenShift)."],
        "snippet": SNIPPET_SECURITY_CONTEXT,
    },
    "K8S_PRIVILEGED": {
        "title": "Contenedor privilegiado o con acceso al host: {detail}",
        "why": "privileged, hostPath o hostNetwork equivalen prácticamente a acceso root al nodo.",
        "steps": ["Elimínalos; si son imprescindibles, documenta la excepción y restríngela con políticas (SCC/Kyverno/Gatekeeper)."],
    },
    "K8S_ADMIN_PORTS": {
        "title": "Puertos de administración expuestos: {ports}",
        "why": ("Jolokia expone JMX por HTTP (lectura/escritura de MBeans y, en configuraciones débiles, ejecución de código); "
                "JDWP permite ejecución remota de código sin autenticación."),
        "steps": [
            "Elimina el containerPort y desactiva el agente (AB_JOLOKIA_OFF=true en imágenes Red Hat OpenJDK).",
            "Si se requiere para monitoreo, protégelo con autenticación y NetworkPolicy, y nunca lo expongas vía Service/Route.",
        ],
        "snippet": SNIPPET_JOLOKIA_OFF,
    },
    "K8S_MUTABLE_IMAGE": {
        "title": "Imagen de despliegue con tag mutable: {images}",
        "why": "El despliegue puede ejecutar una imagen diferente a la escaneada por TMAS.",
        "steps": ["Despliega por digest (@sha256) la misma imagen que se escaneó."],
        "snippet": SNIPPET_PIN_IMAGE,
    },
    "K8S_NO_LIMITS": {
        "title": "Deployment sin límites de recursos",
        "why": "Un pod sin límites puede agotar los recursos del nodo (DoS a otras cargas).",
        "steps": ["Define resources.requests y resources.limits de CPU y memoria."],
    },
    "K8S_NO_PROBES": {
        "title": "Deployment sin liveness/readiness probes",
        "why": "Sin probes, instancias degradadas siguen recibiendo tráfico.",
        "steps": ["Agrega probes a /actuator/health/liveness y /actuator/health/readiness."],
    },
    "K8S_CONFIGMAP_SECRETS": {
        "title": "Credenciales en claro en el ConfigMap: {keys}",
        "why": "Los ConfigMaps no se cifran ni se protegen como Secrets, y suelen imprimirse en logs (como en este pipeline).",
        "steps": [
            "Rota esas credenciales.",
            "Deja solo referencias ${VAR} en el ConfigMap e inyecta los valores desde un Secret (envFrom/secretKeyRef).",
        ],
        "snippet": SNIPPET_SECRET_REF,
    },
    "K8S_ACTUATOR": {
        "title": "Endpoints sensibles de Actuator expuestos: {endpoints}",
        "why": "env, heapdump, configprops o jolokia pueden revelar credenciales o memoria; shutdown permite apagar la app.",
        "steps": ["Expón solo health,info, usa show-details=never y un puerto de gestión que no salga por el Service/Route."],
        "snippet": SNIPPET_ACTUATOR,
    },
    "K8S_DEBUG_LOGGING": {
        "title": "Logging detallado configurado: {items}",
        "why": "DEBUG/TRACE o show-sql pueden escribir datos personales o parámetros sensibles en los logs.",
        "steps": ["Usa INFO/WARN en ambientes productivos; habilita DEBUG solo de forma temporal."],
    },
    # ------------------------------------------------------------ POM seguridad
    "POM_HTTP_REPO": {
        "title": "pom.xml: repositorios Maven sin TLS: {urls}",
        "why": "Dependencias descargadas por http pueden ser alteradas en tránsito.",
        "steps": ["Usa https:// o, mejor, un mirror corporativo definido en settings.xml."],
    },
    "POM_REPOS_IN_POM": {
        "title": "pom.xml: {count} repositorio(s) declarados en el pom",
        "why": ("Declarar repositorios en el pom en lugar de un mirror único en settings.xml abre la puerta a dependency "
                "confusion (el mismo artefacto resuelto desde un origen no esperado)."),
        "steps": ["Centraliza en un mirror de Nexus/Artifactory (mirrorOf=*) en settings.xml y elimina <repositories> del pom."],
    },
    "POM_KNOWN_CVE": {
        "title": "pom.xml: {dep} {version} con {cve}",
        "why": "{desc}. Versión corregida: {fixed}.",
        "steps": ["Actualiza la dependencia (o quita la versión fija para que el BOM de Spring Boot la gestione)."],
    },
})


SNIPPET_BREAKER_BLOCKING = """# Azure DevOps: un breaker de seguridad debe detener el pipeline
- task: Bash@3
  displayName: Breaker - CxOne
  continueOnError: false        # o elimina la propiedad (false por defecto)

# GitLab CI
sast:
  allow_failure: false

# GitHub Actions
- name: Trivy
  continue-on-error: false"""

SNIPPET_PIN_ACTION = """# Antes
- uses: actions/checkout@v4
# Después: fijada por SHA completo (el comentario conserva la versión legible)
- uses: actions/checkout@<sha-de-40-caracteres>  # v4.x.y"""

KB.update({
    # ------------------------------------------------------------ Definición del pipeline
    "PDEF_TOLERATED_SECURITY": {
        "title": "{count} control(es) de seguridad/calidad configurados para no bloquear ({file})",
        "why": ("Con continueOnError / allow_failure / continue-on-error el paso puede fallar y el pipeline sigue: "
                "los breakers quedan como informativos y el código vulnerable se puede desplegar."),
        "steps": [
            "Quita la tolerancia a fallos en breakers, escáneres y tests.",
            "Si necesitas un periodo de adopción, limítalo a ramas de feature con una condición y ponle fecha de fin.",
        ],
        "snippet": SNIPPET_BREAKER_BLOCKING,
    },
    "PDEF_TOLERATED_OTHER": {
        "title": "{count} paso(s) toleran fallos ({file})",
        "why": "Errores en estos pasos no detienen el pipeline; revisa que sea intencional.",
        "steps": ["Confirma que cada paso con tolerancia a fallos sea realmente opcional."],
    },
    "PDEF_SECRETS": {
        "title": "Secretos en claro en la definición del pipeline ({file})",
        "why": "Cualquiera con acceso de lectura al repositorio o a la descarga de logs los ve.",
        "steps": [
            "Rota los valores expuestos.",
            "Muévelos a variables secretas, Variable Groups con Key Vault, GitHub Secrets o CI/CD variables protegidas y enmascaradas.",
        ],
    },
    "PDEF_MUTABLE_REFS": {
        "title": "Templates referenciados por rama ({file}): {refs}",
        "why": "Cualquier commit en esa rama cambia el pipeline de todos los proyectos que lo usan, sin revisión propia.",
        "steps": ["Referencia los templates por tag o commit y actualízalos de forma controlada."],
        "snippet": SNIPPET_PIN_TEMPLATE,
    },
    "PDEF_PERSIST_CREDENTIALS": {
        "title": "El checkout persiste credenciales de git ({file})",
        "why": "El token queda en .git/config y cualquier paso posterior (o herramienta de terceros) puede usarlo.",
        "steps": ["Usa persistCredentials: false (Azure) o persist-credentials: false (GitHub) salvo que un paso haga push."],
    },
    "PDEF_SYSTEM_DEBUG": {
        "title": "Debug del sistema activo en el pipeline ({file})",
        "why": "system.debug / ACTIONS_STEP_DEBUG / CI_DEBUG_TRACE imprimen variables y comandos; CI_DEBUG_TRACE incluso expone secretos.",
        "steps": ["Desactívalo en la definición; habilítalo solo puntualmente al relanzar una ejecución."],
    },
    "PDEF_SET_X": {
        "title": "Scripts con 'set -x' ({file}, líneas {lines})",
        "why": "set -x imprime cada comando expandido; si usa variables con credenciales, quedan en el log.",
        "steps": ["Quita set -x o desactívalo (set +x) alrededor de comandos que usan secretos."],
    },
    "PDEF_LATEST_IMAGES": {
        "title": "Imágenes con tag mutable en la definición ({file}): {images}",
        "why": "Builds no reproducibles y riesgo de ejecutar una imagen alterada.",
        "steps": ["Fija las imágenes por versión o digest @sha256."],
        "snippet": SNIPPET_PIN_IMAGE,
    },
    "PDEF_PIPE_SHELL": {
        "title": "Scripts remotos con curl|bash en la definición ({file}, líneas {lines})",
        "why": "Se ejecuta código remoto sin verificar integridad con acceso a los secretos del pipeline.",
        "steps": ["Descarga, verifica checksum/firma y ejecuta; o versiona el script en el repo de templates."],
        "snippet": SNIPPET_VERIFY_DOWNLOAD,
    },
    "PDEF_TLS": {
        "title": "Verificación TLS deshabilitada en la definición ({file}, líneas {lines})",
        "why": "Permite ataques MITM sobre descargas y llamadas a APIs.",
        "steps": ["Elimina -k/--insecure/sslVerify=false; agrega la CA corporativa al truststore si es necesario."],
    },
    "PDEF_UNPINNED_ACTIONS": {
        "title": "{count} GitHub Action(s) sin fijar por SHA ({file})",
        "why": "Un tag (@v4) puede moverse: si el repositorio de la acción se compromete, tu workflow ejecuta el código nuevo.",
        "steps": ["Fija cada acción de terceros por el SHA completo del commit (Dependabot puede mantenerlas)."],
        "snippet": SNIPPET_PIN_ACTION,
    },
    "PDEF_PR_TARGET": {
        "title": "Workflow con pull_request_target ({file})",
        "why": "Se ejecuta con secretos y permisos de escritura sobre código de PRs externos: vector clásico de robo de secretos.",
        "steps": ["Usa pull_request; si necesitas pull_request_target, no hagas checkout del código del PR ni ejecutes sus scripts."],
    },
    "PDEF_PERMISSIONS": {
        "title": "Permisos del GITHUB_TOKEN sin acotar ({file})",
        "why": "Sin bloque permissions (o con write-all) el token tiene más permisos de los necesarios.",
        "steps": ["Declara permissions: contents: read a nivel workflow y amplía solo por job."],
    },
    # ------------------------------------------------------------ Otros escáneres / ejecución
    "SCANNER_VULNS": {
        "title": "{scanner}: {critical} Critical / {high} High",
        "why": "El escáner reporta vulnerabilidades de severidad alta.",
        "steps": [
            "Revisa el detalle en el log del escáner y actualiza las dependencias o imágenes afectadas.",
            "Si el pipeline no falla con estos hallazgos, configura el umbral de severidad (p. ej. --exit-code 1 --severity HIGH,CRITICAL en Trivy).",
        ],
    },
    "SCANNER_LEAKS": {
        "title": "Gitleaks encontró {leaks} secreto(s) en el repositorio",
        "why": "Hay credenciales versionadas en el código o en el historial de git.",
        "steps": ["Rota cada secreto, elimínalo del código y, si aplica, del historial (git filter-repo)."],
    },
    "SCANNER_FINDINGS": {
        "title": "{scanner}: {count} hallazgo(s)",
        "why": "El escáner reporta hallazgos pendientes.",
        "steps": ["Revisa el detalle en el log del escáner y corrige o documenta excepciones."],
    },
    "RUN_ATTEMPTS": {
        "title": "La descarga contiene {attempts} intentos de ejecución; se analizó el #{attempt}",
        "why": "El pipeline se relanzó. Un intento anterior puede haber fallado por otra causa.",
        "steps": ["Usa --all-attempts para analizar y comparar todos los intentos."],
    },
})


def lookup(key: str) -> Dict[str, Any]:
    return KB.get(key) or KB["SONAR_GENERIC"]
