plugins {
    java
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
    // BouncyCastle JCE provider — RSA, ECDSA, AES, SHA algorithms
    implementation("org.bouncycastle:bcprov-jdk18on:1.78.1")

    // BouncyCastle PKIX — X.509 certs, CSR, CRL, OCSP, CMS/PKCS#7
    implementation("org.bouncycastle:bcpkix-jdk18on:1.78.1")
}

tasks.withType<JavaCompile> {
    options.encoding = "UTF-8"
}
