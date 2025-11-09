//import burp.api.montoya.http.message.HttpHeader;
//import burp.api.montoya.http.message.HttpRequestResponse;
//import burp.api.montoya.http.message.requests.HttpRequest;
//import burp.api.montoya.http.message.responses.HttpResponse;
//import com.alibaba.fastjson2.JSONException;
//
//import java.io.IOException;
//import java.util.ArrayList;
//import java.util.List;
//
//public class Main {
//    public static void main(String[] args) {
//        // 假设rr是从HTTP框架中获取的请求响应数据
//        HttpRequestResponse rr = getHttpRequestResponse(); // 实际场景中获取数据的方法
//
//        try {
//            // 追加数据到指定文件
//            HttpDataJsonSaver.appendHttpData("data/http_records.json", rr);
//            System.out.println("数据保存成功");
//        } catch (IOException e) {
//            System.err.println("文件操作失败：" + e.getMessage());
//        } catch (JSONException e) {
//            System.err.println("JSON格式错误：" + e.getMessage());
//        }
//    }
//
//    // 模拟获取HttpRequestResponse数据（实际场景中无需此方法）
//    private static HttpRequestResponse getHttpRequestResponse() {
//        // 此处仅为示例，实际应根据你的HTTP框架实现
//        return new HttpRequestResponse() {
//            @Override
//            public HttpRequest request() {
//                // 模拟请求对象
//                return new HttpRequest() {
//                    @Override
//                    public String method() { return "GET"; }
//                    @Override
//                    public String url() { return "https://example.com"; }
//                    @Override
//                    public List<HttpHeader> headers() {
//                        List<HttpHeader> headers = new ArrayList<>();
//                        headers.add(new HttpHeader("Accept", "application/json"));
//                        return headers;
//                    }
//                    @Override
//                    public byte[] body() { return "".getBytes(); }
//                    @Override
//                    public String bodyToString() { return ""; }
//                };
//            }
//
//            @Override
//            public HttpResponse response() {
//                // 模拟响应对象
//                return new HttpResponse() {
//                    @Override
//                    public int statusCode() { return 200; }
//                    @Override
//                    public List<HttpHeader> headers() {
//                        List<HttpHeader> headers = new ArrayList<>();
//                        return headers;
//                    }
//                    @Override
//                    public byte[] body() { return "{\"result\":\"success\"}".getBytes(); }
//                    @Override
//                    public String bodyToString() { return "{\"result\":\"success\"}"; }
//                };
//            }
//        };
//    }
//}