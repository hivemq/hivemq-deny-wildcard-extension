plugins {
    alias(libs.plugins.hivemq.extension)
    alias(libs.plugins.defaults)
    alias(libs.plugins.license)
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
    }
}

dependencies {
    implementation(libs.commonsLang)
}

@Suppress("UnstableApiUsage")
testing {
    suites {
        withType<JvmTestSuite> {
            useJUnitJupiter(libs.versions.junit.jupiter)
        }
        "test"(JvmTestSuite::class) {
            dependencies {
                implementation(libs.mockito)
            }
        }
    }
}

license {
    header = rootDir.resolve("HEADER")
    mapping("java", "SLASHSTAR_STYLE")
}
