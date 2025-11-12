import burp.api.montoya.collaborator.CollaboratorClient;
import com.alibaba.fastjson2.JSON;
import com.alibaba.fastjson2.JSONWriter;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;

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
    //  transient 修饰：序列化时忽略（避免保存客户端实例）
    public transient Map<String, CollaboratorClient> domainToClientMap = new HashMap<>();
    public Config.DnslogType donlogType = Config.DnslogType.COLLABORATOR;

    // 扫描选项
    public boolean fastJsonScanEnabled = true; // 默认启用 FastJson 扫描
    public boolean log4jScanEnabled = true;    // 默认启用 Log4j 扫描
    public boolean springScanEnabled = true; // 默认启用 Swagger 扫描
    // 日志设置
    public boolean logEnabled = true;          // 默认启用日志保存
    public String logPath = System.getProperty("user.home") + "/.burp/jaysenscanlog";
    public int logRetentionDays = 7;


    // 私有构造方法（防止外部实例化）
    private DnslogConfig() {}

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
                // 初始化 transient 字段
                config.domainToClientMap = new HashMap<>();
                return config;
            }
        } catch (Exception e) {
            System.err.println("加载配置文件失败，使用默认配置: " + e.getMessage());
        }
        // 直接创建新实例
        return new DnslogConfig();
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