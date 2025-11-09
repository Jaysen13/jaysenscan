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