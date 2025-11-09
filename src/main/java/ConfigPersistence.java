import com.alibaba.fastjson2.JSON;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;

public class ConfigPersistence {
    // 配置文件路径（Burp插件目录下的dnslog_config.json）
    private static final String CONFIG_PATH = System.getProperty("user.home") + "/.burp/dnslog_config.json";

    // 保存配置到文件
    public static void saveConfig(DnslogConfig config) {
        try {
            // 确保父目录（若不存在则创建）
            File configFile = new File(CONFIG_PATH);
            File parentDir = configFile.getParentFile();
            if (!parentDir.exists()) {
                parentDir.mkdirs();
            }

            // 序列化配置对象为JSON并写入文件
            try (FileWriter writer = new FileWriter(configFile)) {
                String json = JSON.toJSONString(config);
                writer.write(json);
            }
        } catch (IOException e) {
            throw new RuntimeException("保存配置文件失败: " + e.getMessage());
        }
    }

    // 从文件加载配置
    public DnslogConfig loadConfig() {
        try {
            File configFile = new File(CONFIG_PATH);
            if (!configFile.exists()) {
                return new DnslogConfig(); // 文件不存在则返回默认配置
            }

            // 从JSON文件反序列化为配置对象
            try (FileReader reader = new FileReader(configFile)) {
                return JSON.parseObject(reader, DnslogConfig.class);
            }
        } catch (IOException e) {
            throw new RuntimeException("加载配置文件失败: " + e.getMessage());
        }
    }
}