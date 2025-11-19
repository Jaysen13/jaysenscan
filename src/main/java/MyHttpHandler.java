import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.HttpHeader;
import com.alibaba.fastjson2.JSON;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public class MyHttpHandler implements HttpHandler {
    private MontoyaApi monApi;
    private MySuiteTab mySuiteTab;
    private final Scan scan;
    private final PluginTaskExecutor executor;
    // 存储“扫描类型_标准化URL”的标记，确保不同类型扫描互不干扰
    static final Set<String> scannedMarks = ConcurrentHashMap.newKeySet();

    public MyHttpHandler(MontoyaApi monApi, MySuiteTab mySuiteTab, PluginTaskExecutor executor) {
        this.monApi = monApi;
        this.mySuiteTab = mySuiteTab;
        this.scan = new Scan(monApi, mySuiteTab, executor);
        this.executor = executor;

    }

    // 定期清理过期标记（每10分钟清理一次）
    public static void scheduleMarkCleanup() {
        ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();
        scheduler.scheduleAtFixedRate(() -> {
            scannedMarks.clear(); // 简单清理，若需精细化可遍历筛选
        }, 10, 5, TimeUnit.MINUTES);
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent httpRequestToBeSent) {
        String targetDomain = DnslogConfig.getInstance().targetDomain;
        String host = httpRequestToBeSent.headerValue("Host");
        String fjson_flag = httpRequestToBeSent.headerValue("JaySen-FastJson-Scan");
        String log4j_flag = httpRequestToBeSent.headerValue("JaySen-Log4j-Scan");
        String spring_flag = httpRequestToBeSent.headerValue("JaySen-Spring-Scan");
        Boolean fjsonEnable = DnslogConfig.getInstance().fastJsonScanEnabled;
        Boolean log4jEnable = DnslogConfig.getInstance().log4jScanEnabled;
        Boolean swgerEnable = DnslogConfig.getInstance().springScanEnabled;
        // 过滤未开启的扫描
        if (!fjsonEnable) fjson_flag = "true";
        if (!log4jEnable) log4j_flag = "true";
        if (!swgerEnable) spring_flag = "true";
        // 未扫描的赋值flag
        if (fjson_flag == null) fjson_flag = "false";
        if (log4j_flag == null) log4j_flag = "false";
        if (spring_flag == null) spring_flag = "false";
//        sendRequestToBeSent(httpRequestToBeSent,monApi);
        // 过滤掉静态资源路径和指定路径
        if (!UrlFilter.isPotenialUrl(httpRequestToBeSent.url())) {
//            monApi.logging().logToOutput("成功过滤掉无价值url: " + httpRequestToBeSent.url());
            return RequestToBeSentAction.continueWith(httpRequestToBeSent);
        }

        // 放行已扫描的数据（所有扫描类型都完成时才放行）
        if (fjson_flag.equals("true") && log4j_flag.equals("true") && spring_flag.equals("true")) {
            return RequestToBeSentAction.continueWith(httpRequestToBeSent);
        }

        // 只扫描指定的目标
        if (targetDomain.isEmpty() || "*".equals(targetDomain) || host.contains(targetDomain)) {
            String standardUrl = standardizeUrl(httpRequestToBeSent.url());

            // 扫描FastJson
            if (fjson_flag.equals("false")) {
                List<JsonData> jsonData = IsJsonRequest.isJsonRequest(httpRequestToBeSent);
                if (!jsonData.isEmpty()) {
                    String mark = "fastjson_" + standardUrl;
                    if (!scannedMarks.contains(mark)) {
                        scannedMarks.add(mark);
                        executor.submit(() -> scan.fastJsonScan(httpRequestToBeSent, jsonData));
                    }
                }
            }

            // 扫描Log4j
            if (log4j_flag.equals("false")) {
                String mark = "log4j_" + standardUrl;
                if (!scannedMarks.contains(mark)) {
                    scannedMarks.add(mark);
                    executor.submit(() -> scan.log4jScan(httpRequestToBeSent));
                }
            }

            // 扫描Spring
            if (spring_flag.equals("false")) {
                String mark = "spring_" + standardUrl;
                if (!scannedMarks.contains(mark)) {
                    scannedMarks.add(mark);
                    executor.submit(() -> scan.springScan(httpRequestToBeSent));
                }
            }
        }

        return RequestToBeSentAction.continueWith(httpRequestToBeSent);
    }

    // 标准化URL，统一格式以避免因参数/大小写差异导致的重复
    private String standardizeUrl(String url) {
        try {
            URL u = new URL(url);
            StringBuilder sb = new StringBuilder();
            sb.append(u.getProtocol().toLowerCase()).append("://");
            sb.append(u.getHost().toLowerCase());
            String path = u.getPath().toLowerCase().replaceAll("/+", "/");
            sb.append(path.isEmpty() ? "/" : path);
            return sb.toString();
        } catch (MalformedURLException e) {
            return url;
        }
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived httpResponseReceived) {
        return null;
    }
    /**
     * 发送完整请求包到RequestToBeSent接口
     */
    private void sendRequestToBeSent(HttpRequestToBeSent request) {
        // 目标接口地址
        String REQUEST_ENDPOINT = "http://127.0.0.1:5000/RequestToBeSent";

        try {
            // 构建完整请求数据（包含所有细节）
            Map<String, Object> data = new HashMap<>();
            Map<String,String> headersMap = new HashMap<>();
            List<HttpHeader> headers = request.headers();
            for (HttpHeader header : headers) {
                headersMap.put(header.name(), header.value());
            }
            data.put("event", "request_to_be_sent");
            data.put("url", request.url());
            data.put("method", request.method());
            data.put("headers", headersMap); // 所有请求头（键值对）
            data.put("body", request.bodyToString()); // 原始请求体
            data.put("timestamp", System.currentTimeMillis());
            // 创建url链接
            URL url = new URL(REQUEST_ENDPOINT);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            // 配置连接参数
            conn.setRequestMethod("POST");
            conn.setDoOutput(true);// 允许发送响应体
            conn.setDoInput(true); // 允许接受响应体
            conn.setConnectTimeout(5000);
            conn.setReadTimeout(5000);
            // 设置请求头
            conn.setRequestProperty("Content-Type", "application/json;charset=UTF-8");
            // 发送请求
            String jsonBody = JSON.toJSONString(data); // Map 转 JSON 字符串
            try (DataOutputStream dos = new DataOutputStream(conn.getOutputStream())) {
                dos.write(jsonBody.getBytes(StandardCharsets.UTF_8));
                dos.flush();
            }
            // 读取响应
            StringBuilder response = new StringBuilder();
            try (BufferedReader br = new BufferedReader(
                    new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = br.readLine()) != null) {
                    response.append(line);
                }
            } finally {
                conn.disconnect(); // 关闭连接
            }
            monApi.logging().logToOutput(response);
        } catch (Exception e) {
            monApi.logging().logToError("构建请求数据失败: " + e.getMessage());
        }
    }

}