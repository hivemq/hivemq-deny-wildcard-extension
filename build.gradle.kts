plugins {
    alias(libs.plugins.hivemq.extension)
    alias(libs.plugins.defaults)
    alias(libs.plugins.oci)
    alias(libs.plugins.license)
}

group = "com.hivemq.extensions"
description = "HiveMQ Extension to deny top level wildcard subscription"

hivemqExtension {
    name = "Deny Wildcard Extension"
    author = "HiveMQ"
    priority = 1000
    startPriority = 1000
    sdkVersion = libs.versions.hivemq.extensionSdk

    resources {
        from("LICENSE")
    }
}

dependencies {
    compileOnly(libs.jetbrains.annotations)
    implementation(libs.commonsLang)
}

oci {
    registries {
        dockerHub {
            optionalCredentials()
        }
    }
    imageMapping {
        mapModule("com.hivemq", "hivemq-community-edition") {
            toImage("hivemq/hivemq-ce")
        }
    }
    imageDefinitions.register("main") {
        allPlatforms {
            dependencies {
                runtime("com.hivemq:hivemq-community-edition:latest") { isChanging = true }
            }
            layers {
                layer("main") {
                    contents {
                        permissions("opt/hivemq/", 0b111_111_101)
                        permissions("opt/hivemq/extensions/", 0b111_111_101)
                        into("opt/hivemq/extensions") {
                            from(zipTree(tasks.hivemqExtensionZip.flatMap { it.archiveFile }))
                        }
                    }
                }
            }
        }
    }
}

@Suppress("UnstableApiUsage")
testing {
    suites {
        withType<JvmTestSuite> {
            useJUnitJupiter(libs.versions.junit.jupiter)
        }
        "test"(JvmTestSuite::class) {
            dependencies {
                compileOnly(libs.jetbrains.annotations)
                implementation(libs.mockito)
            }
        }
    }
}

license {
    header = rootDir.resolve("HEADER")
    mapping("java", "SLASHSTAR_STYLE")
}
