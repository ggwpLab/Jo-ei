// Route Gradle through Jōei for every project on this machine.
// Location: ~/.gradle/init.d/jo-ei.init.gradle.kts
allprojects {
    repositories {
        // Replace declared repositories with the proxy so nothing bypasses it.
        removeAll { true }
        maven {
            url = uri("http://localhost:8080/maven/")
            isAllowInsecureProtocol = true // plain HTTP on localhost
        }
    }
}
