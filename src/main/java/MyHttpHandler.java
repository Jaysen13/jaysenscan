import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.http.InterceptedRequest;
import burp.api.montoya.proxy.http.ProxyResponseToBeSentAction;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.List;
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
        String reqToBeSent_flag = httpRequestToBeSent.headerValue("JaysenReqToBeSent");
        Boolean fjsonEnable = DnslogConfig.getInstance().fastJsonScanEnabled;
        Boolean log4jEnable = DnslogConfig.getInstance().log4jScanEnabled;
        Boolean swgerEnable = DnslogConfig.getInstance().springScanEnabled;
        Boolean cryptEnable = DnslogConfig.getInstance().cryptoEnabled;
        // 过滤未开启的扫描
        if (!fjsonEnable) fjson_flag = "true";
        if (!log4jEnable) log4j_flag = "true";
        if (!swgerEnable) spring_flag = "true";
        if (!cryptEnable) reqToBeSent_flag = "true";
        // 未扫描的赋值flag
        if (fjson_flag == null) fjson_flag = "false";
        if (log4j_flag == null) log4j_flag = "false";
        if (spring_flag == null) spring_flag = "false";
        if (reqToBeSent_flag == null) reqToBeSent_flag = "false";
        // 过滤掉静态资源路径和指定路径
        if (!UrlFilter.isPotenialUrl(httpRequestToBeSent.url())) {
            return RequestToBeSentAction.continueWith(httpRequestToBeSent);
        }

        // 放行已扫描的数据（所有扫描类型都完成时才放行）
        if (fjson_flag.equals("true") && log4j_flag.equals("true") && spring_flag.equals("true") && reqToBeSent_flag.equals("true")) {
            return RequestToBeSentAction.continueWith(httpRequestToBeSent);
        }

        // 只扫描/加密指定的目标
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

            // 调用加密请求数据包
            if (reqToBeSent_flag.equals("false")) {
                // 加密回去并请求
                HttpRequest newRequest = MyProxyRequestHandler.sendRequest(httpRequestToBeSent, "RequestToBeSent",monApi).withAddedHeader("JaysenReqToBeSent","true");
                return RequestToBeSentAction.continueWith(newRequest);
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

    //下面这个方法中完成解密响应数据包
    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived httpResponseReceived) {
        String targetDomain = DnslogConfig.getInstance().targetDomain;
        String host = httpResponseReceived.headerValue("Host");
        Boolean cryptEnable = DnslogConfig.getInstance().cryptoEnabled;
        String respReceived_flag = httpResponseReceived.headerValue("JaysenRespReceived");
        // 已加密的标记
        String reqToBeSent_flag = httpResponseReceived.initiatingRequest().headerValue("JaysenReqToBeSent");
        if (!cryptEnable) respReceived_flag = "true";
        if (respReceived_flag == null) respReceived_flag = "false";
        if (reqToBeSent_flag == null) reqToBeSent_flag = "false";
        // 只解密已加密的数据包
        if (respReceived_flag.equals("false") && reqToBeSent_flag.equals("true")) {
            // 解密操作（可以显示在burp上面）
//            monApi.logging().logToOutput("[DEBUG] handleHttpResponseReceived\n"+httpResponseReceived);
            HttpResponse newRespon = MyProxyRequestHandler.sendResponse(httpResponseReceived, "ResponseReceived",monApi);
            return ResponseReceivedAction.continueWith(newRespon.withAddedHeader("JaysenRespReceived","true"));
        }

        return ResponseReceivedAction.continueWith(httpResponseReceived);
    }

}