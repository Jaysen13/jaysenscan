import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.*;
import java.util.List;

public class MyHttpHandler implements HttpHandler {
    private MontoyaApi monApi;
    private MySuiteTab mySuiteTab;
    private final Scan scan;
    private final PluginTaskExecutor executor;

    public MyHttpHandler(MontoyaApi monApi, MySuiteTab mySuiteTab, PluginTaskExecutor executor) {
        this.monApi = monApi;
        this.mySuiteTab = mySuiteTab;
        this.scan = new Scan(monApi,mySuiteTab,executor);
        this.executor = executor;
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent httpRequestToBeSent) {
        String targetDomain = DnslogConfig.getInstance().targetDomain;
        String host = httpRequestToBeSent.headerValue("Host");
        String fjson_flag = httpRequestToBeSent.headerValue("JaySen-FastJson-Scan");
        String log4j_flag = httpRequestToBeSent.headerValue("JaySen-Log4j-Scan");
        if (fjson_flag == null) {
            fjson_flag = "false";
        }
        if (log4j_flag == null) {
            log4j_flag = "false";
        }
        // 放行已扫描的数据
        if (fjson_flag.equals("true") && log4j_flag.equals("true")) {
            return RequestToBeSentAction.continueWith(httpRequestToBeSent);
        }
        // 只扫描指定的目标
        if (targetDomain == "" || targetDomain.equals("*")) {
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
            }
        }
        return RequestToBeSentAction.continueWith(httpRequestToBeSent);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived httpResponseReceived) {
        return null;
    }


}
