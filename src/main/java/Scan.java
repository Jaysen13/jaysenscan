import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.alibaba.fastjson2.JSONArray;
import com.alibaba.fastjson2.JSONObject;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class Scan {
    private final MontoyaApi montoyaApi;
    private MySuiteTab mySuiteTab;
    private PluginTaskExecutor executor;
    Boolean logEnable;
    private SaveLogFile saveLogFile;

    public Scan(MontoyaApi montoyaApi,MySuiteTab mySuiteTab,PluginTaskExecutor executor) {
        this.montoyaApi = montoyaApi;
        this.mySuiteTab = mySuiteTab;
        this.executor = executor;
        this.logEnable = DnslogConfig.getInstance().logEnabled;
        this.saveLogFile = new SaveLogFile();
    }

    /**
     * 对HTTP请求的所有JSON数据进行替换并发送
     * @param request 原始HTTP请求
     * @param rawDatas 需要替换的json数据列表
     */
    public void fastJsonScan(HttpRequestToBeSent request, List<JsonData> rawDatas) {
        String topDomain1 = "fjson";
        String topDomain2 = UUID.randomUUID().toString().replace("-", "");
            try {
                String timestamp = String.valueOf(System.currentTimeMillis());
                Config config = new Config(timestamp,topDomain1+topDomain2,DnslogConfig.getInstance().collaboratorDomain);
                // 解析Config类中的fastjsonPayload为JSONArray
                JSONArray payloads = JSONArray.parseArray(config.fastjsonPayload);
                // 遍历所有待替换的JSON数据（来自GET参数、POST参数、请求体）
                for (JsonData rawData : rawDatas){
                    // 循环遍历Payload集合，逐个发送
                    for (int i = 0; i < payloads.size(); i++) {

                        Object payloadObj = payloads.get(i);
                        String payloadStr;

                        // 判断 Payload 类型：JSONObject 或 JSONArray
                        if (payloadObj instanceof JSONObject) {
                            payloadStr = ((JSONObject) payloadObj).toJSONString();
                        } else if (payloadObj instanceof JSONArray) {
                            payloadStr = ((JSONArray) payloadObj).toJSONString(); // 数组类型直接序列化
                        } else {
                            this.montoyaApi.logging().logToOutput("Payload[" + (i + 1) + "] 不是 JSON 对象/数组，跳过");
                            continue;
                        }
//                        this.montoyaApi.logging().logToOutput("[DEBUG]payload: " + payloadStr);
                        // 根据JSON数据来源位置，替换对应的部分
                        HttpRequest modifiedRequest = replaceJsonInRequest(request, rawData, payloadStr);
                        // 添加标记头
                        modifiedRequest = modifiedRequest.withAddedHeader("JaySen-FastJson-Scan","true");
                        // 发送修改后的请求
                        HttpRequestResponse attackReqResp = this.montoyaApi.http().sendRequest(modifiedRequest);
                        if (logEnable) {
                            // 加入已发送请求的存储日志中
                            saveLogFile.addToBatch(attackReqResp);
                        }
                        // 不立即检查DNSLOG，而是添加到批量缓存
                        CheckDnslogResult.getInstance().addToBatch(topDomain2, attackReqResp);

                    }
                }
            }
            catch (Exception e) {
                this.montoyaApi.logging().logToError("FastJSON扫描过程出错：" + e.getMessage());
            }
    }

    // 参数类型改为List接口，提高灵活性
    public void fastJsonScan(List<HttpRequest> requests, List<List<JsonData>> rawDatass) {
        String topDomain1 = "fjson";
        String topDomain2 = UUID.randomUUID().toString().replace("-", "");
        try {
            // 边界检查：确保请求列表和JSON数据列表的长度一致
            if (requests.size() != rawDatass.size()) {
                this.montoyaApi.logging().logToError("请求数量与JSON数据列表数量不匹配，终止扫描");
                return;
            }

            String timestamp = String.valueOf(System.currentTimeMillis());
            // 初始化配置
            Config config = new Config(timestamp,topDomain1+topDomain2,DnslogConfig.getInstance().collaboratorDomain);
            JSONArray payloads = JSONArray.parseArray(config.fastjsonPayload);

            // 遍历每个请求，通过索引关联对应的JSON数据列表（一一对应）
            for (int i = 0; i < requests.size(); i++) {
                HttpRequest originalRequest = requests.get(i);
                List<JsonData> rawDatas = rawDatass.get(i);  // 当前请求对应的JSON数据列表

                // 若当前请求无JSON数据，跳过
                if (rawDatas == null || rawDatas.isEmpty()) {
                    this.montoyaApi.logging().logToOutput("请求[" + i + "]无JSON数据，跳过扫描");
                    continue;
                }

                // 遍历当前请求的所有JSON数据
                for (JsonData rawData : rawDatas) {
                    // 遍历所有payload，替换并发送
                    for (int p = 0; p < payloads.size(); p++) {
                        JSONObject payload = payloads.getJSONObject(p);
                        String payloadStr = payload.toJSONString();

                        // 替换JSON数据
                        HttpRequest modifiedRequest = replaceJsonInRequest(originalRequest, rawData, payloadStr);
                        // 基于替换后的请求添加标记头
                        modifiedRequest = modifiedRequest.withAddedHeader("JaySen-FastJson-Scan", "true");

                        // 发送请求
                        HttpRequestResponse attackReqResp = this.montoyaApi.http().sendRequest(modifiedRequest);
//                        Extension.attackReqResps.add(attackReqResp);
                        if (logEnable) {
                            saveLogFile.addToBatch(attackReqResp);
                        }
                        // 不立即检查DNSLOG，而是添加到批量缓存
                        CheckDnslogResult.getInstance().addToBatch(topDomain2,attackReqResp);
                    }
                }
            }

//            montoyaApi.logging().logToOutput("所有请求的FastJSON扫描已完成");
        } catch (Exception e) {
            this.montoyaApi.logging().logToError("FastJSON扫描出错：" + e.getMessage());
        }
    }




    /**
     * 根据JSON数据的位置，替换请求中的对应部分为payload
     */
    private HttpRequest replaceJsonInRequest(HttpRequest rawRequest, JsonData rawData, String payloadStr) {
        // 对payload进行URL编码（适用于GET/POST参数，请求体JSON无需编码）
        String encodedPayload = URLEncoder.encode(payloadStr, StandardCharsets.UTF_8)
                .replace("+", "%20"); // 确保空格编码为%20（符合URL规范）

        switch (rawData.getSourceType()) {
            case REQUEST_BODY:
                // 替换请求体（保留其他请求头、参数等，仅修改body）
                return rawRequest.withBody(payloadStr);

            case GET_PARAM:
                // 修正：GET查询参数的正确类型是 QUERY
                HttpParameter getParam = HttpParameter.parameter(
                        rawData.getParamName(),  // 参数名
                        encodedPayload,         // 编码后的payload
                        HttpParameterType.URL  // 正确类型：QUERY（对应URL中的?后的参数）
                );
                // 仅更新当前参数，其他GET参数保持不变
                return rawRequest.withUpdatedParameters(getParam);

            case POST_PARAM:
                // POST表单参数类型为 BODY（正确）
                HttpParameter postParam = HttpParameter.parameter(
                        rawData.getParamName(),  // 参数名
                        encodedPayload,         // 编码后的payload
                        HttpParameterType.BODY   // 正确类型：BODY（对应application/x-www-form-urlencoded的表单参数）
                );
                // 仅更新当前参数，其他POST参数保持不变
                return rawRequest.withUpdatedParameters(postParam);

            default:
                return rawRequest;
        }
    }


    /**
     * Log4j 全版本漏洞探测
     * */
    public void log4jScan(HttpRequestToBeSent request) {
        String topDomain1 = "log4j";
        String topDomain2 = UUID.randomUUID().toString().replace("-", "");
        try {
            String timestamp = String.valueOf(System.currentTimeMillis());
            // 初始化配置
            Config config = new Config(timestamp,topDomain1+topDomain2,DnslogConfig.getInstance().collaboratorDomain);

            if (config.log4jPayload == null || config.log4jPayload.isEmpty()) {
                this.montoyaApi.logging().logToError("Log4j探测失败：Config未配置log4jPayload");
                return;
            }

            // 关键：log4jPayload是字符串数组，直接解析为JSONArray（无需JSONObject）
            JSONArray payloads = JSONArray.parseArray(config.log4jPayload);

            // 遍历Payload：直接用getString(i)获取字符串，无需getJSONObject
            for (int i = 0; i < payloads.size(); i++) {
                // 修复：getString(i) 提取字符串类型的Payload
                String payloadStr = payloads.getString(i);
                if (payloadStr == null || payloadStr.trim().isEmpty()) {
                    this.montoyaApi.logging().logToOutput("跳过空Payload[" + (i + 1) + "]");
                    continue;
                }

                // 参数值URL编码（请求头无需编码）
                String encodedPayload = URLEncoder.encode(payloadStr, StandardCharsets.UTF_8)
                        .replace("+", "%20");

                // 替换所有请求头和参数（原有逻辑不变）
                HttpRequest modifiedRequest = replaceAllHeaders(request, payloadStr);
                modifiedRequest = replaceAllParameters(modifiedRequest, encodedPayload);
                modifiedRequest = modifiedRequest.withAddedHeader("JaySen-Log4j-Scan", "true")
                        .withAddedHeader("JaySen-Log4j-Payload-Index", String.valueOf(i + 1));

                // 发送请求
                HttpRequestResponse attackReqResp = this.montoyaApi.http().sendRequest(modifiedRequest);
                if (logEnable) {
                    // 保存日志
                    saveLogFile.addToBatch(attackReqResp);
                }
                // 暂不校验dnslog  添加缓存
                CheckDnslogResult.getInstance().addToBatch(topDomain2,attackReqResp);

            }

//            montoyaApi.logging().logToOutput("Log4j全方位探测所有Payload已发送完成");
        } catch (Exception e) {
            this.montoyaApi.logging().logToError("Log4j全方位扫描出错：" + e.getMessage());
        }
    }

    /**
     * 替换所有非关键请求头的值为Payload（保留必要头，防止请求失效）
     */
    private HttpRequest replaceAllHeaders(HttpRequestToBeSent request, String payloadStr) {
        HttpRequest modifiedRequest = request;
        // 定义需要保留的关键头（避免替换后请求无法正常发送）
        List<String> reservedHeaders = new ArrayList<>();
        reservedHeaders.add("Host");          // 必须保留，否则目标地址失效
        reservedHeaders.add("Content-Length");// 必须保留，否则请求体长度不匹配
//        reservedHeaders.add("Content-Type");  // 保留，确保POST表单格式正确
        reservedHeaders.add("Connection");    // 保留，维持连接状态

        // 遍历所有请求头，替换非关键头的值
        for (HttpHeader header : request.headers()) {
            String headerName = header.name();
            // 跳过关键头，替换其他头的值
            if (!reservedHeaders.contains(headerName)) {
                modifiedRequest = modifiedRequest.withUpdatedHeader(headerName, payloadStr);
            }
        }
        return modifiedRequest;
    }

    /**
     * 替换所有参数的值为编码后的Payload（GET/POST表单参数）
     */
    private HttpRequest replaceAllParameters(HttpRequest request, String encodedPayload) {
        HttpRequest modifiedRequest = request;
        // 遍历所有参数（包括GET的QUERY参数、POST的BODY参数）
        for (HttpParameter param : request.parameters()) {
            HttpParameterType paramType = param.type();
            // 按参数类型创建新参数（同名，值为编码后的Payload）
            HttpParameter newParam = switch (paramType) {
                case URL -> HttpParameter.parameter(param.name(), encodedPayload, HttpParameterType.URL);
                case BODY -> HttpParameter.parameter(param.name(), encodedPayload, HttpParameterType.BODY);
                case JSON -> HttpParameter.parameter(param.name(), encodedPayload, HttpParameterType.JSON);
                default -> param; // 其他参数类型（如COOKIE）暂不替换，可根据需求扩展
            };
            // 更新参数值（API自动覆盖原有参数）
            modifiedRequest = modifiedRequest.withUpdatedParameters(newParam);
        }
        return modifiedRequest;
    }

    /**
     * spring未授权访问扫描（优化版）
     */
    public void springScan(HttpRequestToBeSent request) {
        String originalUrl = request.url();

        // 1. 先判断是否为潜在API URL，不是则直接返回
        if (!UrlFilter.isPotentialApiUrl(originalUrl)) {
            montoyaApi.logging().logToOutput("跳过非API URL的spring扫描: " + originalUrl);
            return;
        }

        // 2. 提取基础路径（主域名+端口）
        String baseUrl;
        try {
            baseUrl = originalUrl.substring(0, originalUrl.indexOf('/', 8));
        } catch (Exception e) {
            baseUrl = originalUrl;
        }

        // 4. 常见的spring路径（优化排序，扫描最常见的）
        List<String> springPaths = DnslogConfig.getInstance().getSpringPaths();

        // 5. 执行扫描（现有逻辑）
        try {
            for (String path : springPaths) {
//                String targetUrl = baseUrl + path;
                // 添加已扫描的标记
                request.withAddedHeader("JaySen-spring-Scan", "true");
                HttpRequestResponse attackReqResp = montoyaApi.http().sendRequest(request.withPath(path));
                montoyaApi.logging().logToOutput("springscan正在扫描: " + attackReqResp.request().url());
                if (attackReqResp.response() == null) {
                    continue;
                }
//                if (logEnable) {
//                    saveLogFile.addToBatch(attackReqResp);
//                }

                if (attackReqResp.response().statusCode() == 200) {
                    String responseBody = attackReqResp.response().bodyToString();
                    if (responseBody.contains("spring") || responseBody.contains("OpenAPI") ||
                            responseBody.contains("API") || responseBody.contains("接口文档")) {
//                        mySuiteTab.addVulnerability("spring未授权访问", targetUrl, response);
                        executor.submit(()->mySuiteTab.addRequestInfo(attackReqResp,"Spring"));
                        montoyaApi.logging().logToOutput("发现spring未授权访问: " + attackReqResp.request().url());
                        // 找到一个就可以停止该基础路径的扫描
                        break;
                    }
                }
            }
        } catch (Exception e) {
            montoyaApi.logging().logToError("spring扫描出错: " + e.getMessage());
        }
    }
}