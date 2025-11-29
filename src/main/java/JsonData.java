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
// 记录JSON数据的来源位置和原始内容
public class JsonData {
    // 位置类型：请求体、GET参数、POST表单参数
    public enum SourceType { REQUEST_BODY, GET_PARAM, POST_PARAM }

    private final String jsonContent; // JSON原始内容
    private final SourceType sourceType; // 来源类型
    private final String paramName; // 参数名（仅GET/POST参数需要，请求体为null）

    public JsonData(String jsonContent, SourceType sourceType, String paramName) {
        this.jsonContent = jsonContent;
        this.sourceType = sourceType;
        this.paramName = paramName;
    }

    // getter方法
    public String getJsonContent() { return jsonContent; }
    public SourceType getSourceType() { return sourceType; }
    public String getParamName() { return paramName; }
}