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

public class CheckDnslogResult {
    private final MontoyaApi montoyaApi;
    private final String ceyeApiKey; // 从UI配置读取的CEYE APIKey
    private String keyWord;
    private Config.DnslogType dnslogType; // 当前使用的DNSlog平台类型
    private final String targetDomain; // 需要检查的目标域名（CEYE或Collaborator）

    // 新增构造方法：接收平台类型、目标域名和MontoyaApi
    public CheckDnslogResult(MontoyaApi montoyaApi, String targetDomain,String keyWord) {
        this.montoyaApi = montoyaApi;
        this.targetDomain = targetDomain;
        // 从UI配置中读取CEYE APIKey（仅CEYE平台需要）
        this.ceyeApiKey = DnslogConfig.getInstance().ceyeApiKey;
        this.keyWord = keyWord;
//        montoyaApi.logging().logToOutput("keyWord=" + keyWord);
    }

    /**
     * 统一检查入口：根据平台类型自动选择检查方式
     */
    public Boolean check() {
        this.dnslogType = DnslogConfig.getInstance().donlogType;

        if (dnslogType == Config.DnslogType.CEYE) {
            return checkCeyeDnslog(this.keyWord);
        } else {
//            montoyaApi.logging().logToOutput("目前配置的类型是 " + dnslogType);
            CollaboratorClient collaboratorClient = DnslogConfig.getInstance().domainToClientMap.get(DnslogConfig.getInstance().collaboratorDomain);
            List<String> result = checkCollaboratorDnslog(collaboratorClient, this.keyWord);
            // 非空返回true
            return !result.isEmpty();
        }
    }

    /**
     * 检查CEYE的DNSlog结果
     */
    private Boolean checkCeyeDnslog(String keyWord) {
        // 校验CEYE APIKey是否存在
        if (ceyeApiKey == null || ceyeApiKey.trim().isEmpty()) {
            montoyaApi.logging().logToError("CEYE APIKey未配置，无法检查结果");
            return false;
        }

        // 构建CEYE API请求URL（使用目标域名作为过滤关键词）
        String url = String.format(
                "http://api.ceye.io/v1/records?token=%s&type=dns&filter=%s",
                ceyeApiKey,
                keyWord
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
//                    montoyaApi.logging().logToOutput("CEYE检测到DNS记录：" + data.toString());
                    return true;
                }
            } else {
                montoyaApi.logging().logToError("CEYE API请求失败，响应码： " + response.statusCode() + url);
            }
        } catch (Exception e) {
            montoyaApi.logging().logToError("CEYE结果检查失败：" + e.getMessage());
        }
        return false;
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
     查询Collaborator的dnslog日志
     * */
    public List<String> checkCollaboratorDnslog(
            CollaboratorClient collabClient,
            String keyword // 搜索关键词
    ) {
        List<String> matchedResults = new ArrayList<>();
//        List<String> aaa = new ArrayList<>();
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
            String queryStr = queryBytes.toString().toLowerCase(); // 转为小写，统一匹配
            // 关键词匹配（包含关键词则视为匹配）
            if (keyword == null || queryStr.contains(keyword.toLowerCase())) {
                // 构建匹配的记录内容（格式：类型 + 内容 + 时间）
                String result = String.format(
                        "%s",
                        queryStr
                );
                matchedResults.add(result);
            }
//            String resultaaa = String.format(
//                    "%s",
//                    queryStr
//            );
//            aaa.add(resultaaa);
        }
//        montoyaApi.logging().logToOutput("查询成功:"+matchedResults);
//        montoyaApi.logging().logToOutput("aaaa:"+aaa);
        return matchedResults;
    }
}

