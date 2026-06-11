plugins {
    id("java")
    application
}
application {
    mainClass.set("Main")   // 你的主类全限定名，如果放在默认包可以只写类名
    applicationDefaultJvmArgs = listOf(
        "--add-opens", "java.base/java.net=ALL-UNNAMED"
    )
}
repositories {
    mavenCentral()
}

dependencies {
    compileOnly("net.portswigger.burp.extensions:montoya-api:2025.8")
    implementation("com.alibaba.fastjson2:fastjson2:2.0.60")
}

// 解决 Java 模块化反射权限问题（必须加，解决 URLDNS/Shiro 反序列化）
tasks.withType<JavaExec> {
    jvmArgs("--add-opens", "java.base/java.net=ALL-UNNAMED")
}

tasks.withType<Test> {
    jvmArgs("--add-opens", "java.base/java.net=ALL-UNNAMED")
}

tasks.withType<JavaCompile> {
    sourceCompatibility = "21"
    targetCompatibility = "21"
    options.encoding = "UTF-8"
}

version = "1.5"

tasks.jar {
    val appName = "JaySenScan"
    val dynamicName = "${appName}-${version}.jar" // 最终产物名：JaySenScan-1.x.jar
    archiveFileName.set(dynamicName)

    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    from(configurations.runtimeClasspath.get().filter { it.isDirectory })
    from(configurations.runtimeClasspath.get().filterNot { it.isDirectory }.map { zipTree(it) })

}