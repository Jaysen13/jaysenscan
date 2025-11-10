
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.collaborator.*;
import burp.api.montoya.collaborator.Interaction;
import burp.api.montoya.core.ByteArray;
import com.alibaba.fastjson2.JSONArray;
import com.alibaba.fastjson2.JSONObject;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import burp.api.montoya.http.message.HttpRequestResponse;
import java.util.*;
import java.util.concurrent.*;
import java.util.stream.IntStream;

public class CheckDnslogResult {
    // 单例实例
    private static CheckDnslogResult instance;

    // 初始化方法
    public static void initialize(MontoyaApi montoyaApi, MySuiteTab mySuiteTab) {
        if (instance == null) {
            instance = new CheckDnslogResult(montoyaApi, mySuiteTab);
        }
    }

    public static CheckDnslogResult getInstance() {
        if (instance == null) {
            throw new IllegalStateException("CheckDnslogResult not initialized. Call initialize() first.");
        }
        return instance;
    }

    // 缓存：key=关键词（如漏洞payload中的唯一标识），value=对应的请求信息列表（可能多个请求用同一关键词）
    private final Map<String, List<HttpRequestResponse>> keywordToRequests = new ConcurrentHashMap<>();

    // 定时任务线程池（单线程即可，避免并发检查冲突）
    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();

    private MySuiteTab mySuiteTab;
    private MontoyaApi montoyaApi;
    private String ceyeApiKey;

    // 私有构造函数，接收必要的参数
    private CheckDnslogResult(MontoyaApi montoyaApi, MySuiteTab mySuiteTab) {
        // 设置实例字段
        this.montoyaApi = montoyaApi;
        this.mySuiteTab = mySuiteTab;
        this.ceyeApiKey = DnslogConfig.getInstance().ceyeApiKey;

        // 参数验证
        if (montoyaApi == null) {
            throw new IllegalArgumentException("MontoyaApi cannot be null");
        }
        if (mySuiteTab == null) {
            throw new IllegalArgumentException("MySuiteTab cannot be null");
        }

        // 初始化时启动定时任务：延迟1分钟后，每1分钟执行一次批量检查
        scheduler.scheduleAtFixedRate(
                this::batchCheckDns,  // 执行的任务
                60,  // 首次执行延迟（秒）
                60,  // 间隔周期（秒）
                TimeUnit.SECONDS
        );

        this.montoyaApi.logging().logToOutput("CheckDnslogResult initialized successfully");
    }

    // 添加关键词及对应的请求到缓存
    public void addToBatch(String keyword, HttpRequestResponse request) {
        // 线程安全地添加到缓存，同一个关键词可能对应多个请求
        keywordToRequests.computeIfAbsent(keyword, k -> new CopyOnWriteArrayList<>())
                .add(request);
    }

    // 批量执行DNS检查的核心方法
    private void batchCheckDns() {
        montoyaApi.logging().logToOutput("定时：开始检查dnslog记录");
        if (keywordToRequests.isEmpty()) {
            return;  // 缓存为空，无需检查
        }

        // 复制当前缓存并清空（避免检查过程中新增的关键词被重复处理）
        Map<String, List<HttpRequestResponse>> currentBatch = new HashMap<>(keywordToRequests);
        keywordToRequests.clear();

        // 执行批量DNS检查（根据配置的DNSlog类型，调用对应的检查逻辑）
        DnslogConfig config = DnslogConfig.getInstance();
        List<String> hitKeywords = new ArrayList<>();  // 记录命中的关键词

        if (config.donlogType == Config.DnslogType.CEYE) {
            // 获取所有dns记录
            JSONArray ceyeDnsResult = getCeyeResult();
            // 将命中的keyword保存
            for (String keyword : currentBatch.keySet()) {
                if (checkKeywordtoDnslog(ceyeDnsResult, keyword)) {
                    hitKeywords.add(keyword);
                }
            }
        } else if (config.donlogType == Config.DnslogType.COLLABORATOR) {
            // 调用Collaborator批量获取交互记录，筛选命中的关键词
            CollaboratorClient client = config.domainToClientMap.get(config.collaboratorDomain);
            if (client != null) {
                // 获取所有dns记录
                JSONArray collaboratorResult = getCollaboratorResult(client);
                // 将命中的keyword保存
                for (String keyword : currentBatch.keySet()) {
                    if (checkKeywordtoDnslog(collaboratorResult, keyword)) {
                        hitKeywords.add(keyword);
                    }
                }
            }
        }

        // 处理命中结果：标记漏洞并记录日志
        for (String hitKeyword : hitKeywords) {
            List<HttpRequestResponse> relatedRequests = currentBatch.get(hitKeyword);
            for (HttpRequestResponse req : relatedRequests) {
                // 标记漏洞（例如添加到结果面板）
                this.mySuiteTab.addRequestInfo(req);
                // 记录日志
                this.montoyaApi.logging().logToOutput("发现漏洞：" + req.request().url() + "（关键词：" + hitKeyword + "）");
            }
        }

        // 记录批量检查结果
        this.montoyaApi.logging().logToOutput("批量DNS检查完成，检查关键词: " + currentBatch.size() + "，命中: " + hitKeywords.size());
    }

    // 判断一个关键词是否在记录中
    private boolean checkKeywordtoDnslog(JSONArray data, String keyword) {
        // 查询是否存在于结果中
        boolean exists = IntStream.range(0, data.size()).anyMatch(i -> data.getString(i).contains(keyword));
        return exists;
    }

    // 获取ceye的所有dns记录
    private JSONArray getCeyeResult() {
        // 校验CEYE APIKey是否存在
        if (this.ceyeApiKey == null || this.ceyeApiKey.trim().isEmpty()) {
            this.montoyaApi.logging().logToError("CEYE APIKey未配置，无法检查结果");
            return new JSONArray();
        }

        // 构建CEYE API请求URL
        String url = String.format(
                "http://api.ceye.io/v1/records?token=%s&type=dns",
                this.ceyeApiKey
        );

        try (HttpClient client = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(5))
                .build()) {

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .timeout(Duration.ofSeconds(5))
                    .GET()
                    .build();

            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() == 200) {
                JSONObject responseJson = JSONObject.parseObject(response.body());
                JSONArray data = responseJson.getJSONArray("data");
                // 如果存在记录，返回true
                if (data != null && data.size() > 0) {
                    this.montoyaApi.logging().logToOutput("CEYE检测到DNS记录数量: " + data.size());
                    JSONArray nameArray = new JSONArray();
                    // 遍历原始数组的每个JSONObject
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
                this.montoyaApi.logging().logToError("CEYE API请求失败，响应码： " + response.statusCode() + " URL: " + url);
            }
        } catch (Exception e) {
            this.montoyaApi.logging().logToError("CEYE结果检查失败：" + e.getMessage());
        }
        return new JSONArray();
    }

    /**
     * 生成Collaborator域名并存储映射关系
     * @return 生成的完整域名（如xxx.oastify.com）
     */
    public static String createCollaborator(MontoyaApi montoyaApi) {
        // 创建Collaborator客户端
        CollaboratorClient client = montoyaApi.collaborator().createClient();
        // 生成Payload并拼接完整域名
        String payload = client.generatePayload(PayloadOption.WITHOUT_SERVER_LOCATION).toString() + ".oastify.com";
        // 存储映射关系（使用DnslogConfig单例的运行时Map）
        DnslogConfig.getInstance().domainToClientMap.put(payload, client);
        // 同时更新配置中的"最后生成的域名"（可选，方便界面显示）
        DnslogConfig.getInstance().collaboratorDomain = payload;
        montoyaApi.logging().logToOutput("生成Collaborator域名：" + payload);
        return payload;
    }

    /**
     * 获取所有Collaborator的dnslog日志
     */
    public JSONArray getCollaboratorResult(CollaboratorClient collabClient) {
        JSONArray collaboratorResults = new JSONArray();
        List<Interaction> interactions = collabClient.getAllInteractions();

        for (Interaction interaction : interactions) {
            // 只处理DNS类型的交互
            if (interaction.type() != InteractionType.DNS) {
                continue;
            }

            // 提取DNS详情（处理Optional）
            Optional<DnsDetails> dnsOpt = interaction.dnsDetails();
            if (!dnsOpt.isPresent()) {
                continue;
            }
            DnsDetails dnsDetails = dnsOpt.get();

            // 提取查询内容并检查关键词（不区分大小写）
            ByteArray queryBytes = dnsDetails.query();
            // 转为小写，统一匹配
            String queryStr = queryBytes.toString().toLowerCase();
            String result = String.format("%s", queryStr);
            collaboratorResults.add(result);
        }
        this.montoyaApi.logging().logToOutput("所有CollaboratorClient记录数量: " + collaboratorResults.size());
        this.montoyaApi.logging().logToOutput(JSONArray.toJSONString(collaboratorResults));
        return collaboratorResults;
    }

    // 插件卸载时关闭定时任务（避免资源泄漏）
    public void shutdown() {
        scheduler.shutdown();
    }
}


//import burp.api.montoya.MontoyaApi;
//import burp.api.montoya.collaborator.*;
//import burp.api.montoya.collaborator.Interaction;
//import burp.api.montoya.core.ByteArray;
//import com.alibaba.fastjson2.JSONArray;
//import com.alibaba.fastjson2.JSONObject;
//import java.net.URI;
//import java.net.http.HttpClient;
//import java.net.http.HttpRequest;
//import java.net.http.HttpResponse;
//import java.time.Duration;
//import java.util.ArrayList;
//import java.util.List;
//import java.util.Optional;
//import burp.api.montoya.http.message.HttpRequestResponse;
//import java.util.*;
//import java.util.concurrent.*;
//import java.util.stream.IntStream;
//
//public class CheckDnslogResult {
//    // 单例模式，确保全局唯一的缓存和定时任务
//    private static CheckDnslogResult instance = new CheckDnslogResult();
//
//    public static CheckDnslogResult getInstance() {
//        return instance;
//    }
//
//    // 缓存：key=关键词（如漏洞payload中的唯一标识），value=对应的请求信息列表（可能多个请求用同一关键词）
//    private final Map<String, List<HttpRequestResponse>> keywordToRequests = new ConcurrentHashMap<>();
//
//    // 定时任务线程池（单线程即可，避免并发检查冲突）
//    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();
//
//    MySuiteTab mySuiteTab;
//    MontoyaApi montoyaApi;
//    String ceyeApiKey;
//    private CheckDnslogResult() {
//        this.ceyeApiKey = DnslogConfig.getInstance().ceyeApiKey;
////        this.montoyaApi = montoyaApi;
//        // 初始化时启动定时任务：延迟1分钟后，每1分钟执行一次批量检查
//        scheduler.scheduleAtFixedRate(
//                this::batchCheckDns,  // 执行的任务
//                60,  // 首次执行延迟（秒）
//                60,  // 间隔周期（秒）
//                TimeUnit.SECONDS
//        );
//    }
//
//    // 添加关键词及对应的请求到缓存
//    public void addToBatch(String keyword, HttpRequestResponse request) {
//        // 线程安全地添加到缓存，同一个关键词可能对应多个请求
//        keywordToRequests.computeIfAbsent(keyword, k -> new CopyOnWriteArrayList<>())
//                .add(request);
////        montoyaApi.logging().logToOutput("成功添加到dns请求缓存" + keywordToRequests);
//    }
//
//    // 批量执行DNS检查的核心方法
//    private void batchCheckDns() {
//        if (keywordToRequests.isEmpty()) {
//            return;  // 缓存为空，无需检查
//        }
//
//        // 复制当前缓存并清空（避免检查过程中新增的关键词被重复处理）
//        Map<String, List<HttpRequestResponse>> currentBatch = new HashMap<>(keywordToRequests);
//        keywordToRequests.clear();
//
//        // 执行批量DNS检查（根据配置的DNSlog类型，调用对应的检查逻辑）
//        DnslogConfig config = DnslogConfig.getInstance();
//        List<String> hitKeywords = new ArrayList<>();  // 记录命中的关键词
//
//        if (DnslogConfig.getInstance().donlogType == Config.DnslogType.CEYE) {
//            // 获取所有dns记录
//            JSONArray ceyeDnsResult = getCeyeResult();
//            // 将命中的keyword保存
//            for (String keyword : currentBatch.keySet()) {
//                if (checkKeywordtoDnslog(ceyeDnsResult,keyword)) {
//                    hitKeywords.add(keyword);
//                }
//            }
//        } else if (DnslogConfig.getInstance().donlogType == Config.DnslogType.COLLABORATOR) {
//            // 调用Collaborator批量获取交互记录，筛选命中的关键词
//            CollaboratorClient client = config.domainToClientMap.get(config.collaboratorDomain);
//            if (client != null) {
//                // 获取所有dns记录
//                JSONArray collaboratorResult = getCollaboratorResult(config.domainToClientMap.get(config.collaboratorDomain));
//                // 将命中的keyword保存
//                for (String keyword : currentBatch.keySet()) {
//                    if(checkKeywordtoDnslog(collaboratorResult,keyword)){
//                        hitKeywords.add(keyword);
//                    };
//                }
//            }
//        }
//
//        // 处理命中结果：标记漏洞并记录日志
//        for (String hitKeyword : hitKeywords) {
//            List<HttpRequestResponse> relatedRequests = currentBatch.get(hitKeyword);
//            for (HttpRequestResponse req : relatedRequests) {
//                // 标记漏洞（例如添加到结果面板）
//                mySuiteTab.addRequestInfo(req);
//                // 记录日志
////                montoyaApi.logging().logToOutput("发现漏洞：" + req.request().url() + "（关键词：" + hitKeyword + "）");
//            }
//        }
//    }
//
//    // 判断一个关键词是否在记录中
//    private boolean checkKeywordtoDnslog(JSONArray data,String keyword) {
//        // 查询是否存在于结果中
//        boolean exists = IntStream.range(0, data.size()).anyMatch(i -> data.getString(i).contains(keyword));
//        return exists;  // 替换为实际检查逻辑
//    }
//
//    // 获取ceye的所有dns记录
//    private JSONArray getCeyeResult() {
//        // 校验CEYE APIKey是否存在
//        if (ceyeApiKey == null || ceyeApiKey.trim().isEmpty()) {
////            montoyaApi.logging().logToError("CEYE APIKey未配置，无法检查结果");
//        }
//
//        // 构建CEYE API请求URL（使用目标域名作为过滤关键词）
//        String url = String.format(
//                "http://api.ceye.io/v1/records?token=%s&type=dns",
//                ceyeApiKey
//        );
//
//        try (HttpClient client = HttpClient.newBuilder()
//                .connectTimeout(Duration.ofSeconds(5))
//                .build()) {
//
//            HttpRequest request = HttpRequest.newBuilder()
//                    .uri(URI.create(url))
//                    .timeout(Duration.ofSeconds(5))
//                    .GET()
//                    .build();
//
//            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
//
//            if (response.statusCode() == 200) {
//                JSONObject responseJson = JSONObject.parseObject(response.body());
//                JSONArray data = responseJson.getJSONArray("data");
//                // 如果存在记录，返回true
//                if (data != null && data.size() > 0) {
////                    montoyaApi.logging().logToOutput("CEYE检测到DNS记录：" + data.toString());
//                    JSONArray nameArray = new JSONArray();
//                    // 遍历原始数组的每个JSONObject
//                    for (int i = 0; i < data.size(); i++) {
//                        JSONObject obj = data.getJSONObject(i);
//                        // 提取name字段值（若存在则添加，避免空指针）
//                        if (obj.containsKey("name")) {
//                            String name = obj.getString("name");
//                            nameArray.add(name);
//                        }
//                    }
//                    return nameArray;
//                }
//            } else {
////                montoyaApi.logging().logToError("CEYE API请求失败，响应码： " + response.statusCode() + url);
//            }
//        } catch (Exception e) {
////            montoyaApi.logging().logToError("CEYE结果检查失败：" + e.getMessage());
//        }
//        return new JSONArray();
//    }
//
//
//    /**
//     * 生成Collaborator域名并存储映射关系
//     * @return 生成的完整域名（如xxx.oastify.com）
//     */
//    public static String createCollaborator(MontoyaApi montoyaApi) {
//        // 创建Collaborator客户端
//        CollaboratorClient client = montoyaApi.collaborator().createClient();
//        // 生成Payload并拼接完整域名
//        String payload = client.generatePayload(PayloadOption.WITHOUT_SERVER_LOCATION).toString() + ".oastify.com";
//        // 存储映射关系（使用DnslogConfig单例的运行时Map）
//        DnslogConfig.getInstance().domainToClientMap.put(payload, client);
//        // 同时更新配置中的"最后生成的域名"（可选，方便界面显示）
//        DnslogConfig.getInstance().collaboratorDomain = payload;
//        montoyaApi.logging().logToOutput("生成Collaborator域名：" + payload);
//        return payload;
//    }
//
//
//    /**
//     获取所有Collaborator的dnslog日志
//     * */
//    public JSONArray getCollaboratorResult(CollaboratorClient collabClient)
//    {
//        JSONArray collaoratorResults = new JSONArray();
//        List<Interaction> interactions = collabClient.getAllInteractions();
//
//        for (Interaction interaction : interactions) {
//            // 只处理DNS类型的交互
//            if (interaction.type() != InteractionType.DNS) {
//                continue;
//            }
//
//            // 提取DNS详情（处理Optional）
//            Optional<DnsDetails> dnsOpt = interaction.dnsDetails();
//            if (!dnsOpt.isPresent()) {
//                continue;
//            }
//            DnsDetails dnsDetails = dnsOpt.get();
//
//            // 提取查询内容并检查关键词（不区分大小写）
//            ByteArray queryBytes = dnsDetails.query();
//            // 转为小写，统一匹配
//            String queryStr = queryBytes.toString().toLowerCase();
//            String resultaaa = String.format(
//                    "%s",
//                    queryStr
//            );
//            collaoratorResults.add(resultaaa);
//        }
////        montoyaApi.logging().logToOutput("所有CollaboratorClient记录:" + JSONObject.toJSONString(collaoratorResults));
//        return collaoratorResults;
//    }
//
//    // 插件卸载时关闭定时任务（避免资源泄漏）
//    public void shutdown() {
//        scheduler.shutdown();
//    }
//}
//
