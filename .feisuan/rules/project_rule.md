
# 开发规范指南

为保证代码质量、可维护性、安全性与可扩展性，请在开发过程中严格遵循以下规范。

## 一、项目基本信息

- **用户工作目录**：`E:\java_project\A_BurpExtender\jaysenscan`
- **代码作者**：lsj31
- **操作系统**：Windows 11
- **构建工具**：Gradle
- **SDK 版本**：JDK 24.0.1
- **目标 Java 版本**：Java 21
- **当前时间**：2025-11-26 09:07:27

## 二、目录结构

```
jaysenscan
├── docs
├── gradle
│   └── wrapper
└── src
    ├── main
    │   └── java
    └── test
        └── java
```

## 三、技术栈要求

- **主框架**：Burp Extension (Montoya API)
- **语言版本**：Java 21
- **核心依赖**：
  - `net.portswigger.burp.extensions:montoya-api:2025.8`
  - `com.alibaba.fastjson2:fastjson2:2.0.60`

## 四、构建工具配置

使用 Gradle 构建项目，配置如下：

```kotlin
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

tasks.jar {
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    from(configurations.runtimeClasspath.get().filter { it.isDirectory })
    from(configurations.runtimeClasspath.get().filterNot { it.isDirectory }.map { zipTree(it) })
}
```

## 五、通用规则总结

1. **编码规范**
   - 所有源码文件采用 UTF-8 编码。
   - 使用 Java 21 语法特性进行开发。
   
2. **依赖管理**
   - 依赖项应尽量使用稳定版本。
   - `compileOnly` 类型用于编译时依赖，如 Burp 插件 API。
   - `implementation` 类型用于运行时依赖，如 FastJSON。

3. **模块划分**
   - 源代码位于 `src/main/java` 目录下。
   - 测试代码位于 `src/test/java` 目录下。
   - 文档资源建议放置于 `docs` 目录中。

## 六、代码风格规范

### 命名规范

| 类型       | 命名方式             | 示例                  |
|------------|----------------------|-----------------------|
| 类名       | UpperCamelCase       | `JaySenScanExtension` |
| 方法/变量  | lowerCamelCase       | `processRequest()`    |
| 常量       | UPPER_SNAKE_CASE     | `MAX_RETRY_COUNT`     |

### 注释规范

- 所有类、方法、字段需添加 **Javadoc** 注释。
- 注释使用中文（第一语言）编写。

### 类型命名规范（阿里巴巴风格）

| 后缀 | 用途说明                     | 示例         |
|------|------------------------------|--------------|
| DTO  | 数据传输对象                 | `ScanResultDTO` |
| DO   | 数据库实体对象               | （本项目暂无） |
| BO   | 业务逻辑封装对象             | `ScanBO`     |
| VO   | 视图展示对象                 | （本项目暂无） |
| Query| 查询参数封装对象             | `ScanQuery`  |

## 七、扩展性与日志规范

### 接口优先原则

- 所有功能模块优先通过接口定义，便于后续扩展和测试。

### 日志记录

- 本项目为 Burp 插件，使用 Montoya 提供的日志机制进行调试输出。

## 八、编码原则总结

| 原则       | 说明                                       |
|------------|--------------------------------------------|
| **SOLID**  | 高内聚、低耦合，增强可维护性与可扩展性     |
| **DRY**    | 避免重复代码，提高复用性                   |
| **KISS**   | 保持代码简洁易懂                           |
| **YAGNI**  | 不实现当前不需要的功能                     |
| **OWASP**  | 防范常见安全漏洞，如注入攻击等             |
