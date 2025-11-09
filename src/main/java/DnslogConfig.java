import burp.api.montoya.collaborator.CollaboratorClient;

import java.util.HashMap;
import java.util.Map;

public class DnslogConfig {
    private static DnslogConfig instance; // 延迟初始化
    private static final ConfigPersistence persistence = new ConfigPersistence();

    // 私有构造方法（防止外部实例化）
    public DnslogConfig() {}

    // 单例模式：首次调用时从文件加载配置
    public static synchronized DnslogConfig getInstance() {
        if (instance == null) {
            try {
                instance = persistence.loadConfig(); // 从文件加载
            } catch (Exception e) {
                // 加载失败时使用默认配置
                instance = new DnslogConfig();
                System.err.println("加载配置失败，使用默认配置: " + e.getMessage());
            }
        }
        return instance;
    }
    // 配置字段
    public String platform = "collaborator";
    public String ceyeApiKey = "";
    public String ceyeApiDomain = "";
    public String collaboratorDomain = "";
    public String targetDomain = "";
    // 存储：collaboratorDomain字符串 -> 对应的CollaboratorClient实例   transient修饰：JSON序列化时会忽略该字段，避免保存失败
    public transient Map<String, CollaboratorClient> domainToClientMap = new HashMap<>();
    public Config.DnslogType donlogType =Config.DnslogType.COLLABORATOR; // 默认值

    // 保存配置（调用此方法将当前配置写入文件）
    public void save() {
        // 保存前将collaboratorDomain置空
        persistence.saveConfig(this);
    }


}