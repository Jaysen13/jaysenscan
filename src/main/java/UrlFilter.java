import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

public class UrlFilter {
    // 静态资源后缀（排除）
    private static final List<String> STATIC_EXTENSIONS = Arrays.asList(
            "js", "css", "png", "jpg", "jpeg", "gif", "ico", "svg", "pdf", "doc", "docx", "xls", "xlsx"
    );

    // API路径关键词（包含则优先扫描）
    private static final List<String> API_KEYWORDS = Arrays.asList(
            "api", "rest", "service", "webapi", "backend", "server", "v1", "v2", "v3"
    );

    // 排除的路径关键词
    private static final List<String> EXCLUDE_KEYWORDS = Arrays.asList(
            "static", "assets", "images", "fonts", "download", "upload"
    );

    // 检查是否为潜在的API服务URL（值得扫描Swagger）
    public static boolean isPotentialApiUrl(String url) {
        try {
            String lowerUrl = url.toLowerCase();
            // 3. 优先包含API关键词的URL
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
                return false;
            }
        }

        // 2. 过滤排除关键词
        for (String keyword : EXCLUDE_KEYWORDS) {
            if (lowerUrl.contains(keyword)) {
                return false;
            }
        }
        return true;
    }
}