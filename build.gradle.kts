plugins {
    java
    checkstyle
    id("com.github.spotbugs") version "6.1.7"
}

group   = "com.pqc"
version = "1.0.0"

java {
    sourceCompatibility = JavaVersion.VERSION_21
    targetCompatibility = JavaVersion.VERSION_21
}

repositories {
    mavenCentral()
}

dependencies {
    implementation("org.bouncycastle:bcprov-jdk18on:1.78.1")
    implementation("org.bouncycastle:bcpkix-jdk18on:1.78.1")

    // SpotBugs annotations (optional — for @SuppressFBWarnings)
    compileOnly("com.github.spotbugs:spotbugs-annotations:4.9.3")
}

tasks.withType<JavaCompile> {
    options.encoding = "UTF-8"
}

// =========================================================================
// Checkstyle — Google Java Style (relaxed for learning project)
// =========================================================================
checkstyle {
    toolVersion = "10.21.4"
    configFile  = file("config/checkstyle/checkstyle.xml")
    isIgnoreFailures = true   // warn, don't break build
    isShowViolations = true
}

// =========================================================================
// SpotBugs — static analysis
// =========================================================================
spotbugs {
    ignoreFailures = true
    showStackTraces = false
    effort = com.github.spotbugs.snom.Effort.DEFAULT
    reportLevel = com.github.spotbugs.snom.Confidence.MEDIUM
}

tasks.withType<com.github.spotbugs.snom.SpotBugsTask> {
    enabled = true
    reports.create("html") { required = true }
    reports.create("xml")  { required = false }
}

// =========================================================================
// Generic `run` task — .\gradlew run -PmainClass=com.pqc.XYZ
// =========================================================================
tasks.register<JavaExec>("run") {
    group       = "demo"
    description = "Run any class: -PmainClass=com.pqc.XYZ"
    mainClass.set(
        project.findProperty("mainClass") as String?
            ?: "com.pqc.ca.CaHierarchyDemo"
    )
    classpath = sourceSets["main"].runtimeClasspath
}

// =========================================================================
// Named shortcut tasks — .\gradlew <taskName>
// =========================================================================
fun demoTask(taskName: String, mainCls: String, desc: String) {
    tasks.register<JavaExec>(taskName) {
        group       = "demo"
        description = desc
        mainClass.set(mainCls)
        classpath = sourceSets["main"].runtimeClasspath
    }
}

// --- Original Task series ---
demoTask("task01", "com.pqc.Task01_RsaKeyPairGeneration",   "RSA key pair generation")
demoTask("task02", "com.pqc.Task02_SelfSignedCaCertificate","Self-signed CA certificate")
demoTask("task03", "com.pqc.Task03_CsrGeneration",          "CSR generation (basic)")
demoTask("task04", "com.pqc.Task04_IssueCertFromCsr",       "Issue certificate from CSR")
demoTask("task05", "com.pqc.Task05_CrlGeneration",          "CRL generation")
demoTask("task06", "com.pqc.Task06_OcspRequestResponse",    "OCSP request/response")
demoTask("task07", "com.pqc.Task07_CmsSignedData",          "CMS/PKCS#7 signed data")
demoTask("task08", "com.pqc.Task08_Pkcs12KeyStore",         "PKCS#12 keystore")

// --- CA Hierarchy ---
demoTask("ca-demo",  "com.pqc.ca.CaHierarchyDemo",                  "Two-tier CA hierarchy (Root CA + Sub CA)")

// --- TLS Server Certificate Pipeline ---
demoTask("tls-step01", "com.pqc.ca.tls.Step01_ServerKeyPairGeneration", "TLS: RSA-2048 server key pair")
demoTask("tls-step02",    "com.pqc.ca.tls.Step02_CsrGeneration",           "TLS: CSR with 10-attribute DN + 5 extensions")
demoTask("tls-pipeline",  "com.pqc.ca.tls.TlsPipelineRunner",             "TLS: Full end-to-end pipeline (key → CSR → cert → verify)")
demoTask("csr-inspect",  "com.pqc.ca.tls.Step02_CsrInspector",           "TLS: Parse cert/server.csr.pem — print all ASN.1 fields and OIDs")

// =========================================================================
// `demos` task — list all available demo tasks
// =========================================================================
tasks.register("demos") {
    group       = "demo"
    description = "List all available demo shortcut tasks"
    doLast {
        println("")
        println("╔══════════════════════════════════════════════════════════════════════╗")
        println("║              pqc-demo — Available Demo Tasks                        ║")
        println("╠══════════════════╦═══════════════════════════════════════════════════╣")
        println("║ Task             ║ Description                                       ║")
        println("╠══════════════════╬═══════════════════════════════════════════════════╣")
        println("║ task01           ║ RSA key pair generation                           ║")
        println("║ task02           ║ Self-signed CA certificate                        ║")
        println("║ task03           ║ CSR generation (basic)                            ║")
        println("║ task04           ║ Issue certificate from CSR                        ║")
        println("║ task05           ║ CRL generation                                    ║")
        println("║ task06           ║ OCSP request/response                             ║")
        println("║ task07           ║ CMS/PKCS#7 signed data                           ║")
        println("║ task08           ║ PKCS#12 keystore                                 ║")
        println("╠══════════════════╬═══════════════════════════════════════════════════╣")
        println("║ ca-demo          ║ Two-tier CA hierarchy (Root + Sub CA)            ║")
        println("╠══════════════════╬═══════════════════════════════════════════════════╣")
        println("║ tls-step01       ║ TLS: RSA-2048 server key pair                    ║")
        println("║ tls-step02       ║ TLS: CSR with 10-attr DN + 5 extensions          ║")
        println("║ tls-pipeline     ║ TLS: Full pipeline — key → CSR → cert → verify   ║")
        println("╠══════════════════╬═══════════════════════════════════════════════════╣")
        println("║ check            ║ Run Checkstyle + SpotBugs                        ║")
        println("║ checkstyleMain   ║ Checkstyle only                                  ║")
        println("║ spotbugsMain     ║ SpotBugs only (report: build/reports/spotbugs/)  ║")
        println("╚══════════════════╩═══════════════════════════════════════════════════╝")
        println("")
        println("  Usage:  .\\gradlew.bat <task>")
        println("  Custom: .\\gradlew.bat run -PmainClass=com.pqc.XYZ")
        println("")
    }
}
