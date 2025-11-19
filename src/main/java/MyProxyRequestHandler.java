import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.proxy.http.InterceptedRequest;
import burp.api.montoya.proxy.http.ProxyRequestHandler;
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction;
import burp.api.montoya.proxy.http.ProxyRequestToBeSentAction;
import com.alibaba.fastjson2.JSON;
import com.alibaba.fastjson2.JSONObject;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.InputStreamReader;
import java.lang.reflect.Parameter;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class MyProxyRequestHandler implements ProxyRequestHandler {
    private MontoyaApi montoyaApi;
    // ThreadLocal类型改为InterceptedRequest（存储原始拦截请求）
    private final ThreadLocal<InterceptedRequest> originalRequestLocal  = new ThreadLocal<>();


    public MyProxyRequestHandler(MontoyaApi montoyaApi) {
        this.montoyaApi = montoyaApi;
    }
    @Override
    public ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest interceptedRequest) {
        originalRequestLocal.set(interceptedRequest);
        return ProxyRequestReceivedAction.continueWith(sendRequestRecceived(interceptedRequest));
    }
    @Override
    public ProxyRequestToBeSentAction handleRequestToBeSent(InterceptedRequest interceptedRequest) {
        return ProxyRequestToBeSentAction.continueWith(interceptedRequest);
    }
    private HttpRequest sendRequestRecceived(InterceptedRequest request) {
        // 目标接口地址
        String REQUEST_ENDPOINT = "http://127.0.0.1:5000/RequestReceived";

        try {
            // 构建完整请求数据（包含所有细节）
            Map<String, Object> data = new HashMap<>();
            Map<String, String> headersMap = new HashMap<>();
            Map<String, String> parametersMap = new HashMap<>();
            // 处理httpheaders
            List<HttpHeader> headers = request.headers();
            for (HttpHeader header : headers) {
                headersMap.put(header.name(), header.value());
            }
            // 处理url的Pramters
            List<ParsedHttpParameter> parameters = request.parameters();
            for (ParsedHttpParameter parameter : parameters) {
                if (parameter.type()==HttpParameterType.URL){
                    parametersMap.put(parameter.name(), parameter.value());
                }
            }
            data.put("paramters", parametersMap);
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
//            montoyaApi.logging().logToOutput(response.toString());
            // 修改后的请求包
            HttpRequest newRequest = request;
            // 解析返回的数据
            JSONObject jsonObject = JSON.parseObject(response.toString());
            Map<String,String> newHeadersMap = (Map<String, String>) jsonObject.get("headers");
            // 将Map<String, String>转回List<HttpHeader>
            for (Map.Entry<String, String> entry : newHeadersMap.entrySet()) {
                HttpHeader newHeader = HttpHeader.httpHeader(entry.getKey(), entry.getValue());
                newRequest = newRequest.withHeader(newHeader);
            }
            // 处理parameters
            Map<String,String> newParametersMap = (Map<String, String>) jsonObject.get("paramters");
            for (Map.Entry<String, String> entry : newParametersMap.entrySet()) {
                HttpParameter parameter = HttpParameter.urlParameter(entry.getKey(), entry.getValue());
                newRequest = newRequest.withParameter(parameter);
            }
            // 读取method
            String newMethod = jsonObject.getString("method");
            // 读取完整body
            String newBody = jsonObject.getString("body");
            newRequest = newRequest.withMethod(newMethod).withBody(newBody);
            montoyaApi.logging().logToOutput("[DEBUG] 新请求如下：");
            montoyaApi.logging().logToOutput(newRequest);
            return newRequest;
        } catch (Exception e) {
            montoyaApi.logging().logToError("构建请求外部数据失败: " + e.getMessage());
        }
        // 若远程接口出现错误，则不更改返回原数据包
        return request;
    }
}
