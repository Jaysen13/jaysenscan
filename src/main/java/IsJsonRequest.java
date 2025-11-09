
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import com.alibaba.fastjson2.JSONArray;
import com.alibaba.fastjson2.JSONObject;
import com.alibaba.fastjson2.JSONException;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

public class IsJsonRequest {

    public static List<JsonData> isJsonRequest(HttpRequestToBeSent request) {
        List<JsonData> jsonDataList = new ArrayList<>();
        String contentType = request.headerValue("Content-Type") != null ? request.headerValue("Content-Type") : "";

        // 1. 检测请求体（整体为JSON）
        String body = request.bodyToString();
        if (isJsonString(body) && !isLog4jPayload(body)) {
            jsonDataList.add(new JsonData(body, JsonData.SourceType.REQUEST_BODY, null));
        }

        // 2. 检测GET查询参数值中的JSON
        List<ParsedHttpParameter> parameters = request.parameters();
        for (HttpParameter param : parameters) {
            String paramValue = param.value();
            if (isJsonString(paramValue) && !isLog4jPayload(paramValue)) {
                jsonDataList.add(new JsonData(paramValue, JsonData.SourceType.GET_PARAM, param.name()));
            }
        }

        // 3. 检测POST表单参数（application/x-www-form-urlencoded）值中的JSON
        if (contentType.toLowerCase().contains("application/x-www-form-urlencoded")) {
            Map<String, String> formParams = parseFormParams(body);
            for (Map.Entry<String, String> entry : formParams.entrySet()) {
                String paramName = entry.getKey();
                String paramValue = entry.getValue();
                if (isJsonString(paramValue) && !isLog4jPayload(paramValue)) {
                    jsonDataList.add(new JsonData(paramValue, JsonData.SourceType.POST_PARAM, paramName));
                }
            }
        }

        return jsonDataList;
    }
    public static List<JsonData> isJsonRequest(HttpRequestResponse request) {
        List<JsonData> jsonDataList = new ArrayList<>();
        String contentType = request.request().headerValue("Content-Type") != null ? request.request().headerValue("Content-Type") : "";

        // 1. 检测请求体（整体为JSON）
        String body = request.request().bodyToString();
        if (isJsonString(body) && !isLog4jPayload(body)) {
            jsonDataList.add(new JsonData(body, JsonData.SourceType.REQUEST_BODY, null));
        }

        // 2. 检测GET查询参数值中的JSON
        List<ParsedHttpParameter> parameters = request.request().parameters();
        for (HttpParameter param : parameters) {
            String paramValue = param.value();
            if (isJsonString(paramValue) && !isLog4jPayload(paramValue)) {
                jsonDataList.add(new JsonData(paramValue, JsonData.SourceType.GET_PARAM, param.name()));
            }
        }

        // 3. 检测POST表单参数（application/x-www-form-urlencoded）值中的JSON
        if (contentType.toLowerCase().contains("application/x-www-form-urlencoded")) {
            Map<String, String> formParams = parseFormParams(body);
            for (Map.Entry<String, String> entry : formParams.entrySet()) {
                String paramName = entry.getKey();
                String paramValue = entry.getValue();
                if (isJsonString(paramValue) && !isLog4jPayload(paramValue)) {
                    jsonDataList.add(new JsonData(paramValue, JsonData.SourceType.POST_PARAM, paramName));
                }
            }
        }

        return jsonDataList;
    }

    // 辅助：判断字符串是否为JSON
    private static boolean isJsonString(String str) {
        if (str == null || str.trim().isEmpty()) return false;
        str = str.trim();

        try {
            str = URLDecoder.decode(str, StandardCharsets.UTF_8);
        } catch (Exception e) {

        }

        try {
            JSONObject.parseObject(str);
            return true;
        } catch (JSONException e1) {
            try {
                JSONArray.parseArray(str);
                return true;
            } catch (JSONException e2) {
                return false;
            }
        }
    }

    // 辅助：解析POST表单参数
    private static Map<String, String> parseFormParams(String body) {
        Map<String, String> params = new HashMap<>();
        if (body == null || body.isEmpty()) return params;
        String[] pairs = body.split("&");
        for (String pair : pairs) {
            String[] keyValue = pair.split("=", 2);
            if (keyValue.length == 2) {
                try {
                    String key = URLDecoder.decode(keyValue[0], StandardCharsets.UTF_8);
                    String value = URLDecoder.decode(keyValue[1], StandardCharsets.UTF_8);
                    params.put(key, value);
                } catch (Exception e) {
                    params.put(keyValue[0], keyValue[1]); // 解码失败用原始值
                }
            }
        }
        return params;
    }
    private static final Pattern LOG4J_PAYLOAD_PATTERN = Pattern.compile(
            "\\$\\{.*j.*n.*d.*i.*:",  // 模糊匹配 ${xxxjxxnxxdxxi:} 格式
            Pattern.CASE_INSENSITIVE  // 忽略大小写（适配 ${JNDi:} 等变形）
    );
    // 辅助判断是否是log4j的payload
    private static boolean isLog4jPayload(String str) {
        if (str == null || str.isEmpty()) return false;
        // 匹配 Log4j JNDI 注入的核心特征（覆盖基础格式和常见绕过）
        return LOG4J_PAYLOAD_PATTERN.matcher(str).find();
    }
}