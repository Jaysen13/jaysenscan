
import com.alibaba.fastjson2.JSONArray;
import com.alibaba.fastjson2.JSONObject;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.stream.IntStream;

public class Main {
    public static void main(String[] args) {
        String keyword = "11fjson";
        JSONArray result = checkCeyeDnslog("json");
        System.out.println(JSONArray.toJSONString(result));
        boolean exists = IntStream.range(0, result.size()).anyMatch(i -> result.getString(i).contains(keyword));
        if (exists) {
            System.out.println(String.format("%s 存在于DnsLog记录中",keyword));
        }
    }
    private static JSONArray checkCeyeDnslog(String keyWord) {

        // 构建CEYE API请求URL（使用目标域名作为过滤关键词）
        String url = String.format(
                "http://api.ceye.io/v1/records?token=%s&type=dns&filter=%s",
                "4c231224a5dffc5f4290b22ffdd29e68",
                keyWord
        );

        try (HttpClient client = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(5))
                .build()) {

            java.net.http.HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .timeout(Duration.ofSeconds(5))
                    .GET()
                    .build();

            java.net.http.HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() == 200) {
                JSONObject responseJson = JSONObject.parseObject(response.body());
                JSONArray data = responseJson.getJSONArray("data");
                // 如果存在记录，返回true
                if (data != null && data.size() > 0) {
                    JSONArray nameArray = new JSONArray();
//                    montoyaApi.logging().logToOutput("CEYE检测到DNS记录：" + data.toString());
                    for (int i = 0; i < data.size(); i++) {
                        JSONObject obj = data.getJSONObject(i);
                        // 提取name字段值（若存在则添加，避免空指针）
                        if (obj.containsKey("name")) {
                            String name = obj.getString("name");
                            nameArray.add(name);
                        }
                    }
                    return nameArray;
                }
            } else {
                System.out.println("CEYE API请求失败，响应码： " + response.statusCode() + url);
            }
        } catch (Exception e) {
            System.out.println("CEYE结果检查失败：" + e.getMessage());
        }
        return new JSONArray();
    }
}