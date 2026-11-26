pluginManagement {
    repositories {
        google()
        // Use a Google-hosted Maven Central mirror to reduce exposure to
        // transient Maven Central rate limits. Keep Maven Central as fallback.
        maven {
            name = "GoogleCloudMavenCentralMirror"
            url = uri("https://maven-central.storage-download.googleapis.com/maven2/")
        }
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        // Mirror Maven Central dependencies first; retain the canonical repo
        // for artifacts that may not yet be present in the mirror.
        maven {
            name = "GoogleCloudMavenCentralMirror"
            url = uri("https://maven-central.storage-download.googleapis.com/maven2/")
        }
        mavenCentral()
    }
}

rootProject.name = "ANTIVIRUS-AL-AI"
include(":app")
