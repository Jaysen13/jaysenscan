/*
 * JaySenScan - Burp Suite 加密环境渗透测试插件
 *
 * Copyright (C) 2025 JaySen (Jaysen13)
 *
 * 本软件采用 CC BY-NC-SA 4.0 许可证进行许可
 * 禁止用于商业售卖，允许非商业使用、修改和分享，衍生品需采用相同许可证
 *
 * 作者：JaySen
 * 邮箱：3147330392@qq.com
 * GitHub：https://github.com/Jaysen13/JaySenScan
 * 许可证详情：参见项目根目录 LICENSE 文件
 */
import burp.api.montoya.collaborator.CollaboratorClient;
import com.alibaba.fastjson2.JSON;
import com.alibaba.fastjson2.JSONWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class DnslogConfig {
    // 单例实例
    private static volatile DnslogConfig instance;
    // 配置文件路径（用户目录下的 .burp 文件夹）
    private static final Path CONFIG_PATH = Paths.get(
            System.getProperty("user.home") + "/.burp/dnslog_config.json"
    );

    // ========================= 原有配置字段 =========================
    public String platform = "collaborator"; // 默认使用 collaborator
    public String ceyeApiKey = "";
    public String ceyeApiDomain = "";
    public String collaboratorDomain = "";
    public String targetDomain = "";
    // transient 修饰：序列化时忽略（避免保存客户端实例）
    public transient Map<String, CollaboratorClient> domainToClientMap = new HashMap<>();
    public Config.DnslogType donlogType = Config.DnslogType.COLLABORATOR;

    // 扫描选项
    public boolean fastJsonScanEnabled = true; // 默认启用 FastJson 扫描
    public boolean log4jScanEnabled = true;    // 默认启用 Log4j 扫描
    public boolean springScanEnabled = true;   // 默认启用 Spring 扫描
    // 日志设置
    public boolean logEnabled = true;          // 默认启用日志保存
    public String logPath = System.getProperty("user.home") + "/.burp/jaysenscanlog";
    public int logRetentionDays = 7;
    // 需过滤的后缀名
    public String filterExtensions = "js,css,png,jpg,jpeg,pdf,gif,ico,svg,doc,docx,xls,xlsx";
    // 需过滤的路径关键词
    public String filterKeywords = "static,assets,images,fonts,download,upload";
    // Spring扫描关键词
    public String springScanKeywords = "api,rest,service,webapi,backend,server,v1,v2,v3";
    // Spring扫描文件路径
    public String springScanFilePath = System.getProperty("user.home") + "/.burp/springapiscan.txt";
    // 存储读取到的Spring路径列表（供外部调用）
    private List<String> springPaths;
    public boolean cryptoEnabled = false; // 是否启用接口加解密（默认关闭）
    public String cryptoApiUrl = "http://127.0.0.1:5000"; // 加解密接口链接（默认值）

    // 私有构造方法（防止外部实例化）
    private DnslogConfig() {
        // 初始化Spring扫描文件并加载路径列表
        initSpringScanFile();
        loadSpringPaths();
    }

    // 单例模式：双重检查锁确保线程安全
    public static DnslogConfig getInstance() {
        if (instance == null) {
            synchronized (DnslogConfig.class) {
                if (instance == null) {
                    instance = loadFromFile(); // 从文件加载配置
                }
            }
        }
        return instance;
    }

    // 从配置文件加载（不存在则返回默认实例）
    private static DnslogConfig loadFromFile() {
        try {
            if (Files.exists(CONFIG_PATH)) {
                // 读取文件内容并反序列化为 DnslogConfig
                String json = Files.readString(CONFIG_PATH, StandardCharsets.UTF_8);
                DnslogConfig config = JSON.parseObject(json, DnslogConfig.class);
                // 初始化 transient 字段和Spring路径
                config.domainToClientMap = new HashMap<>();
                config.initSpringScanFile(); // 确保文件存在
                config.loadSpringPaths();    // 加载路径列表
                return config;
            }
        } catch (Exception e) {
            System.err.println("加载配置文件失败，使用默认配置: " + e.getMessage());
        }
        // 直接创建新实例（会触发构造方法中的初始化）
        return new DnslogConfig();
    }

    // 初始化Spring扫描路径文件（自动生成并写入预设内容）
    private void initSpringScanFile() {
        try {
            File file = new File(springScanFilePath);
            // 检查父目录是否存在，不存在则创建
            File parentDir = file.getParentFile();
            if (parentDir != null && !parentDir.exists()) {
                parentDir.mkdirs(); // 递归创建目录
            }

            // 如果文件不存在或为空，则写入预设路径
            if (!file.exists() || file.length() == 0) {
                // 预设的Spring扫描路径列表
                List<String> defaultPaths = Arrays.asList(
                        "/actuator",  // Spring Boot Actuator 监控端点
                        "/actuator/health",
                        "/actuator/info",

                        // -------------------------- Swagger3 (SpringFox) 路径 --------------------------
                        "/swagger-ui.html",  // Swagger2 旧版UI路径（兼容用）
                        "/swagger-ui",      // Swagger3 新版UI路径
                        "/swagger-ui/index.html",  // Swagger3 完整UI路径
                        "/v3/api-docs/**",   // Swagger3 接口文档JSON数据
                        "/v2/api-docs",      // Swagger2 兼容路径
                        "/api-docs",         // 通用API文档路径
                        "/swagger-resources/",  // Swagger 资源文件
                        "/swagger-resources/configuration/ui",  // Swagger UI 配置
                        "/swagger-resources/configuration/security",  // Swagger 安全配置
                        "/springfox-swagger-ui",  // SpringFox 扩展资源路径
                        "/webjars",       // Swagger UI 依赖的WebJars资源

                        // -------------------------- Druid 监控路径 --------------------------
                        "/druid/login.html",  // Druid 登录页
                        "/druid/",            // Druid 监控主页
                        "/druid/index.html",  // Druid 完整主页路径
                        "/druid/datasource.html",  // 数据源监控页
                        "/druid/sql.html",    // SQL执行监控页
                        "/druid/uri.html",    // URI访问监控页
                        "/druid/session.html",// 会话监控页
                        "/druid/webapp.html", // Web应用监控页
                        "/druid/filter.html", // 过滤器监控页

                        // -------------------------- 国产框架/扩展路径 --------------------------
                        "/doc.html",          // Knife4j（Swagger增强）默认UI路径
                        "/knife4j",           // Knife4j 资源路径
                        "/spring-ui.html",
                        "/spring-ui",
                        "/spring-resources",
                        "/spring.json",
                        "/spring"
                );

                // 写入文件（一行一个路径）
                try (FileWriter writer = new FileWriter(file)) {
                    for (String path : defaultPaths) {
                        writer.write(path + System.lineSeparator()); // 换行符适配系统
                    }
                }
                System.out.println("Spring扫描路径文件已生成：" + springScanFilePath);
            } else {
                System.out.println("Spring扫描路径文件已存在：" + springScanFilePath);
            }
        } catch (IOException e) {
            System.err.println("生成Spring扫描路径文件失败：" + e.getMessage());
        }
    }

    // 加载文件内容为List<String>（去空行和trim处理）
    private void loadSpringPaths() {
        try {
            // 读取所有行，过滤空行并trim
            springPaths = Files.readAllLines(Paths.get(springScanFilePath), StandardCharsets.UTF_8)
                    .stream()
                    .map(String::trim)
                    .filter(line -> !line.isEmpty())
                    .collect(Collectors.toList());
        } catch (IOException e) {
            System.err.println("读取Spring扫描路径文件失败：" + e.getMessage());
            springPaths = new ArrayList<>(); // 异常时返回空列表
        }
    }

    // 外部调用接口：获取Spring路径列表（返回副本，避免外部修改）
    public List<String> getSpringPaths() {
        return new ArrayList<>(springPaths);
    }

    // 当文件路径修改后，重新加载列表（供配置面板调用）
    public void reloadSpringPaths() {
        initSpringScanFile(); // 确保新路径文件存在
        loadSpringPaths();    // 重新加载
    }

    // 保存配置到文件
    public void save() {
        try {
            // 确保父目录存在（不存在则创建）
            File parentDir = CONFIG_PATH.getParent().toFile();
            if (!parentDir.exists()) {
                parentDir.mkdirs();
            }

            // 序列化时忽略 transient 字段（domainToClientMap 不会被保存）
            String json = JSON.toJSONString(this, JSONWriter.Feature.PrettyFormat); // 格式化输出，便于调试
            Files.writeString(CONFIG_PATH, json, StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new RuntimeException("保存配置文件失败: " + e.getMessage(), e);
        }
    }

    // 提供配置文件路径的 getter（便于调试或日志输出）
    public String getConfigFilePath() {
        return CONFIG_PATH.toString();
    }
}