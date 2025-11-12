import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.*;
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
    // 已扫描的基础路径缓存（防止重复扫描）
    static final Set<String> scannedBasePaths = ConcurrentHashMap.newKeySet();
    public MyHttpHandler(MontoyaApi monApi, MySuiteTab mySuiteTab, PluginTaskExecutor executor) {
        this.monApi = monApi;
        this.mySuiteTab = mySuiteTab;

        this.scan = new Scan(monApi,mySuiteTab,executor);
        this.executor = executor;
    }
    // 定期清理扫描缓存
    public static void scheduleCacheCleanup() {
        ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();
        scheduler.scheduleAtFixedRate(() -> {
            scannedBasePaths.clear();
        }, 1, 10, TimeUnit.MINUTES);
    }
    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent httpRequestToBeSent) {
        String targetDomain = DnslogConfig.getInstance().targetDomain;
        String host = httpRequestToBeSent.headerValue("Host");
        String fjson_flag = httpRequestToBeSent.headerValue("JaySen-FastJson-Scan");
        String log4j_flag = httpRequestToBeSent.headerValue("JaySen-Log4j-Scan");
        String swager_flag = httpRequestToBeSent.headerValue("JaySen-Swagger-Scan");
        Boolean fjsonEnable = DnslogConfig.getInstance().fastJsonScanEnabled;
        Boolean log4jEnable = DnslogConfig.getInstance().log4jScanEnabled;
        Boolean swgerEnable = DnslogConfig.getInstance().springScanEnabled;
        // 过滤未开启的扫描
        if (!fjsonEnable) {
            fjson_flag = "true";
        }
        if (!log4jEnable) {
            log4j_flag = "true";
        }
        if (!swgerEnable){
            swager_flag = "true";
        }
        // 未扫描的赋值flag
        if (fjson_flag == null) {
            fjson_flag = "false";
        }
        if (log4j_flag == null) {
            log4j_flag = "false";
        }
        if (swager_flag == null) {
            swager_flag = "false";
        }

        // 过滤掉静态资源路径和指定路径
        if (!UrlFilter.isPotenialUrl(httpRequestToBeSent.url())) {
            monApi.logging().logToOutput("成功过滤掉无价值url: "+httpRequestToBeSent.url());
            return RequestToBeSentAction.continueWith(httpRequestToBeSent);
        }
        // 放行已扫描的数据
        if (fjson_flag.equals("true") && log4j_flag.equals("true")) {
            return RequestToBeSentAction.continueWith(httpRequestToBeSent);
        }
        // 检查是否已扫描过该基础路径，避免重复扫描
        if (scannedBasePaths.contains(httpRequestToBeSent.url())) {
            return RequestToBeSentAction.continueWith(httpRequestToBeSent);
        }
        // 只扫描指定的目标
        if (targetDomain == "" || targetDomain.equals("*")) {
            scannedBasePaths.add(httpRequestToBeSent.url());
            // 扫描fastjson
            if (fjson_flag.equals("false")) {
                // 判断是否为json类型，并提取json数据
                List<JsonData> jsonData = IsJsonRequest.isJsonRequest(httpRequestToBeSent);

                if (!jsonData.isEmpty()) {
                    // 后台执行fastjson扫描
                    executor.submit(() -> scan.fastJsonScan(httpRequestToBeSent, jsonData));
                }
            }

            // 扫描log4j
            if (log4j_flag.equals("false")) {
                executor.submit(() -> scan.log4jScan(httpRequestToBeSent));
            }
            // 扫描swagger接口
            if (swager_flag.equals("false")) {
                executor.submit(() -> scan.springScan(httpRequestToBeSent));
            }
        } else {
            if (host.contains(targetDomain)) {
                // 扫描fastjson
                if (fjson_flag.equals("false")) {
                    // 判断是否为json类型，并提取json数据
                    List<JsonData> jsonData = IsJsonRequest.isJsonRequest(httpRequestToBeSent);

                    if (!jsonData.isEmpty()) {
                        // 后台执行fastjson扫描
                        executor.submit(() -> scan.fastJsonScan(httpRequestToBeSent, jsonData));
                    }
                }

                // 扫描log4j
                if (log4j_flag.equals("false")) {
                    executor.submit(() -> scan.log4jScan(httpRequestToBeSent));
                }
                // 扫描spring接口
                if (swager_flag.equals("false")) {
                    executor.submit(() -> scan.springScan(httpRequestToBeSent));
                }
            }
        }
        return RequestToBeSentAction.continueWith(httpRequestToBeSent);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived httpResponseReceived) {
        return null;
    }


}
