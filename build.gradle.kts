plugins {
    id("com.hivemq.extension")
    id("com.github.hierynomus.license")
    id("io.github.sgtsilvio.gradle.defaults")
    id("org.asciidoctor.jvm.convert")
}

group = "com.hivemq.extensions"
description = "HiveMQ Extension to deny top level wildcard subscription"

hivemqExtension {
    name.set("Deny Wildcard Extension")
    author.set("HiveMQ")
    priority.set(1000)
    startPriority.set(1000)
    sdkVersion.set("${property("hivemq-extension-sdk.version")}")
}

dependencies {
    implementation("org.apache.commons:commons-lang3:${property("commons-lang.version")}")
    //slf4j
}

/* ******************** resources ******************** */

val prepareAsciidoc by tasks.registering(Sync::class) {
    from("README.adoc").into({ temporaryDir })
}

tasks.asciidoctor {
    dependsOn(prepareAsciidoc)
    sourceDir(prepareAsciidoc.map { it.destinationDir })
}

hivemqExtension.resources {
    from("LICENSE")
    from("README.adoc") { rename { "README.txt" } }
    from(tasks.asciidoctor)
}

/* ******************** test ******************** */

dependencies {
    testImplementation("org.junit.jupiter:junit-jupiter:${property("junit-jupiter.version")}")
    testImplementation("org.mockito:mockito-core:${property("mockito.version")}")
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
