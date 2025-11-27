import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.http.*;
import com.alibaba.fastjson2.JSON;
import com.alibaba.fastjson2.JSONObject;
import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class MyProxyRequestHandler implements ProxyRequestHandler , ProxyResponseHandler {
    private MontoyaApi montoyaApi;

    public MyProxyRequestHandler(MontoyaApi montoyaApi) {
        this.montoyaApi = montoyaApi;
    }

    @Override
    public ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest interceptedRequest) {
        return ProxyRequestReceivedAction.continueWith(interceptedRequest);
    }

    // 在下面函数中调用接口解密请求数据包
    @Override
    public ProxyRequestToBeSentAction handleRequestToBeSent(InterceptedRequest interceptedRequest) {
        String targetDomain = DnslogConfig.getInstance().targetDomain;
        String host = interceptedRequest.headerValue("Host");
        Boolean cryptEnable = DnslogConfig.getInstance().cryptoEnabled;
        String reqReceived_flag = interceptedRequest.headerValue("JaysenReqReceived");
        if (!cryptEnable) reqReceived_flag = "true";
        if (reqReceived_flag == null) reqReceived_flag = "false";

        // 只解密指定的目标
        if (targetDomain.isEmpty() || "*".equals(targetDomain) || host.contains(targetDomain)) {
            // 调用解密请求数据包
            if (reqReceived_flag.equals("false")) {
                // 解密操作（可以显示在burp上面）
                HttpRequest newRequest = sendRequest(interceptedRequest, "RequestReceived",montoyaApi).withAddedHeader("JaysenReqReceived","true");
                return ProxyRequestToBeSentAction.continueWith(newRequest);
            }
        }
        return ProxyRequestToBeSentAction.continueWith(interceptedRequest);
    }

    // 在下面这个函数中完成加密响应数据包
    @Override
    public ProxyResponseReceivedAction handleResponseReceived(InterceptedResponse interceptedResponse) {
        Boolean cryptEnable = DnslogConfig.getInstance().cryptoEnabled;
        String respToBeSent_flag = interceptedResponse.headerValue("JaysenRespToBeSent");
        // 响应体已解密的标志
        String respReceived_flag = interceptedResponse.headerValue("JaysenRespReceived");
        if (!cryptEnable) respToBeSent_flag = "true";
        if (respToBeSent_flag == null) respToBeSent_flag = "false";
        // 只加密已解密的目标
        if (respToBeSent_flag.equals("false") && respReceived_flag.equals("true")) {
            // 加密操作（可以显示在burp上面）
            HttpResponse newRespon = sendResponse(interceptedResponse, "ResponseToBeSent",montoyaApi);
            return ProxyResponseReceivedAction.continueWith(newRespon.withAddedHeader("JaysenRespToBeSent","true"));
        }
        return ProxyResponseReceivedAction.continueWith(interceptedResponse);
    }


    @Override
    public ProxyResponseToBeSentAction handleResponseToBeSent(InterceptedResponse interceptedResponse) {
        return ProxyResponseToBeSentAction.continueWith(interceptedResponse);
    }

    public static HttpRequest sendRequest(HttpRequest request, String path,MontoyaApi montoyaApi) {
        // 目标接口地址
        String REQUEST_ENDPOINT = DnslogConfig.getInstance().cryptoApiUrl.endsWith("/") ? DnslogConfig.getInstance().cryptoApiUrl + path : DnslogConfig.getInstance().cryptoApiUrl + "/" + path;
        HttpRequest newRequest = request;
        try {
            // 构建完整请求数据（包含所有细节）
            Map<String, Object> data = new HashMap<>();
            Map<String, String> headersMap = new HashMap<>();
            Map<String, String> parametersMap = new HashMap<>();
            // 处理httpheaders
            List<HttpHeader> headers = request.headers();
            for (HttpHeader header : headers) {
                headersMap.put(header.name(), header.value());
                // 去除掉请求头
                newRequest = newRequest.withRemovedHeader(header.name());
            }
            // 处理url的Pramters
            List<ParsedHttpParameter> parameters = request.parameters();
            for (ParsedHttpParameter parameter : parameters) {
                if (parameter.type() == HttpParameterType.URL) {
                    parametersMap.put(parameter.name(), parameter.value());
                    // 去除掉参数
                    newRequest = newRequest.withRemovedParameters(parameter);
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
            // 解析返回的数据
            JSONObject jsonObject = JSON.parseObject(response.toString());
            Map<String, String> newHeadersMap = (Map<String, String>) jsonObject.get("headers");
            // 将Map<String, String>转回List<HttpHeader>
            for (Map.Entry<String, String> entry : newHeadersMap.entrySet()) {
                HttpHeader newHeader = HttpHeader.httpHeader(entry.getKey(), entry.getValue());
                newRequest = newRequest.withHeader(newHeader);
            }
            // 处理parameters
            Map<String, String> newParametersMap = (Map<String, String>) jsonObject.get("paramters");
            for (Map.Entry<String, String> entry : newParametersMap.entrySet()) {
                HttpParameter parameter = HttpParameter.urlParameter(entry.getKey(), entry.getValue());
                newRequest = newRequest.withParameter(parameter);
            }
            // 读取method
            String newMethod = jsonObject.getString("method");
            // 读取完整body
            String newBody = jsonObject.getString("body");
            newRequest = newRequest.withMethod(newMethod).withBody(newBody);
            return newRequest;
        } catch (Exception e) {
            montoyaApi.logging().logToError("构建请求外部数据失败: " + e.getMessage());
        }
        // 若远程接口出现错误，则不更改返回原数据包
        return request;
    }

    public static HttpResponse sendResponse(HttpResponse reponse, String path,MontoyaApi montoyaApi) {
        // 目标接口地址
        String REQUEST_ENDPOINT = DnslogConfig.getInstance().cryptoApiUrl.endsWith("/") ? DnslogConfig.getInstance().cryptoApiUrl + path : DnslogConfig.getInstance().cryptoApiUrl + "/" + path;
        HttpResponse newRespon = reponse;
        try {
            // 构建完整请求数据（包含所有细节）
            Map<String, Object> data = new HashMap<>();
            Map<String, String> headersMap = new HashMap<>();
            // 处理httpheaders
            List<HttpHeader> headers = reponse.headers();
            for (HttpHeader header : headers) {
                headersMap.put(header.name(), header.value());
                // 去除掉请求头
                newRespon = newRespon.withRemovedHeader(header.name());
            }
            data.put("headers", headersMap); // 所有请求头（键值对）
            data.put("body", reponse.bodyToString()); // 原始请求体
//            montoyaApi.logging().logToOutput("[DEBUG] sendResponse:\n " + reponse);
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
            // 解析返回的数据
            JSONObject jsonObject = JSON.parseObject(response.toString());
            Map<String, String> newHeadersMap = (Map<String, String>) jsonObject.get("headers");
            // 将Map<String, String>转回List<HttpHeader>
            for (Map.Entry<String, String> entry : newHeadersMap.entrySet()) {
                newRespon = newRespon.withAddedHeader(entry.getKey(),entry.getValue());
            }
            // 读取完整body
            String newBody = jsonObject.getString("body");
            newRespon = newRespon.withBody(newBody);
            return newRespon;
        } catch (Exception e) {
            montoyaApi.logging().logToError("构建请求外部数据失败: " + e.getMessage());
        }
        // 若远程接口出现错误，则不更改返回原数据包
        return reponse;
    }
}
