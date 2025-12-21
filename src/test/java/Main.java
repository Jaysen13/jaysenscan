import java.io.DataOutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.security.cert.X509Certificate;

public class Main {
    public static void main(String[] args) {
        // 第一步：忽略HTTPS自签证书（本地测试用，生产环境请勿使用）
        disableSSLVerification();

        HttpURLConnection conn = null;
        try {
            URL url = new URL("http://127.0.0.1:5000/11");
            conn = (HttpURLConnection) url.openConnection();

            // 1. 配置连接参数
            conn.setRequestMethod("POST"); // POST请求必须设置
            conn.setDoOutput(true); // 允许写入请求体（POST必备）
            conn.setConnectTimeout(5000);
            conn.setReadTimeout(5000);
            // 可选：设置Content-Type（根据服务端要求，比如JSON/表单）
            conn.setRequestProperty("Content-Type", "application/json;charset=UTF-8");

            // 2. 发送POST请求体（关键：必须写入请求体，否则POST请求不完整）
            // 若服务端允许空请求体，可写空字符串，但仍需执行写入操作触发请求
            String requestBody = ""; // 按需修改为实际请求体（如JSON字符串）
            try (DataOutputStream dos = new DataOutputStream(conn.getOutputStream())) {
                dos.write(requestBody.getBytes(StandardCharsets.UTF_8));
                dos.flush();
            }

            // 3. 核心：获取响应状态码（必须在发送请求体后调用）
            int responseCode = conn.getResponseCode();
            System.out.println("HTTP响应状态码：" + responseCode);

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            // 4. 关闭连接，释放资源
            if (conn != null) {
                conn.disconnect();
            }
        }
    }

    // 辅助方法：忽略HTTPS证书校验（本地测试专用）
    private static void disableSSLVerification() {
        try {
            TrustManager[] trustAllCerts = new TrustManager[]{
                    new X509TrustManager() {
                        public X509Certificate[] getAcceptedIssuers() { return null; }
                        public void checkClientTrusted(X509Certificate[] certs, String authType) {}
                        public void checkServerTrusted(X509Certificate[] certs, String authType) {}
                    }
            };
            SSLContext sc = SSLContext.getInstance("TLS");
            sc.init(null, trustAllCerts, new java.security.SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
            HttpsURLConnection.setDefaultHostnameVerifier((hostname, session) -> true);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}