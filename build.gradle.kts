plugins {
    id("java")
}

repositories {
    mavenCentral()
}

dependencies {
    compileOnly("net.portswigger.burp.extensions:montoya-api:2025.8")
    implementation("com.alibaba.fastjson2:fastjson2:2.0.60")
}

tasks.withType<JavaCompile> {
    sourceCompatibility = "21"
    targetCompatibility = "21"
    options.encoding = "UTF-8"
}

version = "1.0"

tasks.jar {
    val appName = "JaySenScan"
    val dynamicName = "${appName}-${version}.jar" // 最终产物名：JaySenScan-1.0.jar
    archiveFileName.set(dynamicName) // 关键修正：替换 archiveName → archiveFileName

    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    from(configurations.runtimeClasspath.get().filter { it.isDirectory })
    from(configurations.runtimeClasspath.get().filterNot { it.isDirectory }.map { zipTree(it) })

}