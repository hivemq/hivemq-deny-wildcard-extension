plugins {
    alias(libs.plugins.hivemq.extension)
    alias(libs.plugins.defaults)
    alias(libs.plugins.license)
    alias(libs.plugins.asciidoctor)
}

group = "com.hivemq.extensions"
description = "HiveMQ Extension to deny top level wildcard subscription"

hivemqExtension {
    name.set("Deny Wildcard Extension")
    author.set("HiveMQ")
    priority.set(1000)
    startPriority.set(1000)
    sdkVersion.set(libs.versions.hivemq.extensionSdk)

    resources {
        from("LICENSE")
        from("README.adoc") { rename { "README.txt" } }
        from(tasks.asciidoctor)
    }
}

dependencies {
    implementation(libs.commonsLang)
}

tasks.asciidoctor {
    sourceDirProperty.set(layout.projectDirectory)
    sources("README.adoc")
    secondarySources { exclude("**") }
}

/* ******************** test ******************** */

dependencies {
    testImplementation(libs.junit.jupiter)
    testImplementation(libs.mockito)
}

tasks.withType<Test>().configureEach {
    useJUnitPlatform()
}

/* ******************** checks ******************** */

license {
    header = rootDir.resolve("HEADER")
    mapping("java", "SLASHSTAR_STYLE")
}

/* ******************** run ******************** */

tasks.prepareHivemqHome {
    hivemqHomeDirectory.set(file("/path/to/a/hivemq/folder"))
}
