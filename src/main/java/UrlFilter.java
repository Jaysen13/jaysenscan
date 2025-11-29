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
import java.util.Arrays;
import java.util.List;

public class UrlFilter {
    // 静态资源后缀（排除）
    private static final List<String> STATIC_EXTENSIONS= Arrays.asList(DnslogConfig.getInstance().filterExtensions.split("\\s*,\\s*"));
    // API路径关键词(触发spring扫描)
    private static final List<String> API_KEYWORDS = Arrays.asList(DnslogConfig.getInstance().springScanKeywords.split("\\s*,\\s*"));
    // 排除的路径关键词
    private static final List<String> EXCLUDE_KEYWORDS = Arrays.asList(DnslogConfig.getInstance().filterKeywords.split("\\s*,\\s*"));

    // 检查是否为潜在的API服务URL（值得扫描Swagger）
    public static boolean isPotentialApiUrl(String url) {
        try {
            String lowerUrl = url.toLowerCase();
            // 优先包含API关键词的URL
            for (String keyword : API_KEYWORDS) {
                if (lowerUrl.contains(keyword)) {
                    return true;
                }
            }
            // 其他情况默认不扫描
            return false;
        } catch (Exception e) {
            return false;
        }
    }
    // 过滤掉无需扫描的url
    public static boolean isPotenialUrl(String url) {
        // 1. 过滤静态资源
        String lowerUrl = url.toLowerCase();
        for (String ext : STATIC_EXTENSIONS) {
            if (lowerUrl.endsWith("." + ext)) {
//                montoyaApi.logging().logToOutput("因为后缀包含"+ext);
                return false;
            }
        }

        // 2. 过滤排除关键词
        for (String keyword : EXCLUDE_KEYWORDS) {
            if (lowerUrl.contains(keyword)) {
//                montoyaApi.logging().logToOutput("因为url包含"+keyword);
                return false;
            }
        }
        return true;
    }
}