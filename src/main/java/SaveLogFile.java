import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.alibaba.fastjson2.JSON;
import com.alibaba.fastjson2.JSONObject;
import com.alibaba.fastjson2.JSONWriter;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;
import java.util.zip.GZIPOutputStream;

/**
 * 优化后的日志存储工具类（解决大文件问题）
 * 特性：
 * 1. JSON Lines格式（每行一个JSON对象），支持流式读写
 * 2. 按大小自动分割文件（默认10MB）
 * 3. GZIP压缩存储（可选）
 * 4. 自动清理过期日志（默认保留30天）
 * 5. 精简字段，去除冗余信息
 */
public class SaveLogFile {
    private final String baseDir; // 日志根目录
    private final String prefix;  // 日志文件前缀
    private final long maxFileSize; // 单个文件最大大小（字节）
    private final int retainDays; // 日志保留天数
    private static final ConcurrentHashMap<String, ReentrantLock> PATH_LOCKS = new ConcurrentHashMap<>();

    // 构造方法：可配置分割大小、保留天数等
    public SaveLogFile() {
        this.baseDir = Config.scanLogPath + "jaysenscanlog/";
        this.prefix = "jaysenscanlog_" + LocalDate.now().format(DateTimeFormatter.ofPattern("yyyyMMdd")) + "_";
        this.maxFileSize = 10 * 1024 * 1024; // 10MB
        this.retainDays = 7; // 保留7天日志
        initDir();
        cleanExpiredLogs(); // 启动时清理过期日志
    }

    // 初始化目录
    private void initDir() {
        File dir = new File(baseDir);
        if (!dir.exists()) {
            dir.mkdirs();
        }
    }

    // 获取当前应写入的文件路径（自动分割）
    private String getCurrentFilePath() {
        // 查找当前日期下的最新文件
        File dir = new File(baseDir);
        File[] files = dir.listFiles((d, name) -> name.startsWith(prefix) && (name.endsWith(".log") || name.endsWith(".log.gz")));
        if (files == null || files.length == 0) {
            return baseDir + prefix + "0.log.gz"; // 初始文件
        }

        // 按序号排序，取最后一个
        File lastFile = files[files.length - 1];
        if (lastFile.length() < maxFileSize) {
            return lastFile.getAbsolutePath();
        } else {
            // 超过大小，创建新文件（序号+1）
            String numStr = lastFile.getName().split("_")[2].split("\\.")[0];
            int num = Integer.parseInt(numStr) + 1;
            return baseDir + prefix + num + ".log.gz";
        }
    }

    // 获取文件对应的锁
    private ReentrantLock getLock(String filePath) {
        String normalizedPath;
        try {
            normalizedPath = new File(filePath).getCanonicalPath();
        } catch (IOException e) {
            normalizedPath = filePath;
        }
        return PATH_LOCKS.computeIfAbsent(normalizedPath, k -> new ReentrantLock());
    }

    // 精简并处理HTTP数据（只保留必要字段，压缩大内容）
    private JSONObject processHttpData(HttpRequestResponse rr) {
        JSONObject data = new JSONObject();
        HttpRequest request = rr.request();
        HttpResponse response = rr.response();

        // 1. 基础信息（必要字段）
        data.put("method", request.method());
        data.put("url", request.url());
        data.put("timestamp", System.currentTimeMillis());

        // 2. 请求头：只保留关键头部（过滤冗余）
        JSONObject reqHeaders = new JSONObject();
        for (HttpHeader header : request.headers()) {
            String name = header.name().toLowerCase();
            // 只保留常见关键头部（可根据需求调整）
            if (name.contains("host") || name.contains("cookie") || name.contains("content-type") || name.contains("user-agent")) {
                reqHeaders.put(header.name(), header.value());
            }
        }
        data.put("reqHeaders", reqHeaders);

        // 3. 请求体：压缩长内容（超过1024字节则压缩）
        String reqBody = request.bodyToString();
        data.put("reqBody", compressIfLarge(reqBody));

        // 4. 响应信息（必要字段）
        if (response != null) {
            data.put("respStatus", response.statusCode());
            // 响应体：压缩长内容
            String respBody = response.bodyToString();
            data.put("respBody", compressIfLarge(respBody));
        }

        return data;
    }

    // 长内容压缩（使用GZIP，Base64编码便于存储）
    private String compressIfLarge(String content) {
        if (content == null || content.length() <= 1024) { // 短内容不压缩
            return content;
        }
        try (ByteArrayOutputStream out = new ByteArrayOutputStream();
             GZIPOutputStream gzip = new GZIPOutputStream(out)) {
            gzip.write(content.getBytes(StandardCharsets.UTF_8));
            gzip.finish();
            return "gzip:" + Base64.getEncoder().encodeToString(out.toByteArray()); // 标记压缩类型
        } catch (IOException e) {
            return content; // 压缩失败则存储原文
        }
    }

    // 追加数据到日志文件（JSON Lines格式）
    public void appendHttpData(HttpRequestResponse rr) throws IOException {
        String filePath = getCurrentFilePath();
        ReentrantLock lock = getLock(filePath);
        lock.lock();
        try (BufferedWriter writer = new BufferedWriter(
                new OutputStreamWriter(
                        new GZIPOutputStream(
                                new FileOutputStream(filePath, true)), // 追加模式
                        StandardCharsets.UTF_8))) {

            // 写入单行JSON（FastJSON禁用格式化，减少体积）
            JSONObject data = processHttpData(rr);
            String jsonLine = JSON.toJSONString(data);
            writer.write(jsonLine);
            writer.newLine(); // 换行分隔

        } finally {
            lock.unlock();
        }
    }

    // 清理过期日志（保留retainDays天内的）
    private void cleanExpiredLogs() {
        LocalDate cutoffDate = LocalDate.now().minusDays(retainDays);
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyyMMdd");
        File dir = new File(baseDir);
        File[] files = dir.listFiles();
        if (files == null) return;

        for (File file : files) {
            try {
                // 解析文件名中的日期（如jaysenscanlog_20240520_0.log.gz）
                String name = file.getName();
                if (name.startsWith("jaysenscanlog_")) {
                    String dateStr = name.split("_")[1];
                    LocalDate fileDate = LocalDate.parse(dateStr, formatter);
                    if (fileDate.isBefore(cutoffDate)) {
                        Files.delete(file.toPath());
                    }
                }
            } catch (Exception e) {
                // 忽略解析失败的文件
            }
        }
    }

    // 清理锁（可选）
    public void cleanLock() {
        try {
            String normalizedPath = new File(baseDir).getCanonicalPath();
            PATH_LOCKS.remove(normalizedPath);
        } catch (IOException e) {
            PATH_LOCKS.remove(baseDir);
        }
    }
}

//import burp.api.montoya.http.message.HttpHeader;
//import burp.api.montoya.http.message.HttpRequestResponse;
//import burp.api.montoya.http.message.requests.HttpRequest;
//import burp.api.montoya.http.message.responses.HttpResponse;
//import com.alibaba.fastjson2.*;
//
//import java.io.File;
//import java.io.IOException;
//import java.nio.charset.StandardCharsets;
//import java.nio.file.Files;
//import java.nio.file.Paths;
//import java.time.LocalDate;
//import java.time.format.DateTimeFormatter;
//import java.util.ArrayList;
//import java.util.List;
//import java.util.Objects;
//import java.util.concurrent.ConcurrentHashMap;
//import java.util.concurrent.locks.ReentrantLock;
//
///**
// * HTTP请求响应数据JSON存储工具类
// * 特性：
// * 1. 处理HttpRequestResponse数据并转换为指定格式
// * 2. 以List<JSONArray>格式追加保存（保持JSON格式完整）
// * 3. 自动创建目录，美化JSON格式
// * 4. 基于文件路径的锁机制，防止并发写入冲突
// */
//public class SaveLogFile {
//    private final String filePath;
//    // 存储文件路径与对应锁的映射（读写共用同一把锁）
//    private static final ConcurrentHashMap<String, ReentrantLock> PATH_LOCKS = new ConcurrentHashMap<>();
//
//    public SaveLogFile() {
//        LocalDate currentDate = LocalDate.now();
//        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyyMMdd");
//        String formattedDate = currentDate.format(formatter);
//        // 假设Config.scanLogPath是全局配置的日志根路径
//        this.filePath = Config.scanLogPath + "jaysenscanlog" + "/jaysenscanlog" + formattedDate + ".json";
//    }
//
//    /**
//     * 获取文件路径对应的锁（同一文件共享同一把锁）
//     */
//    private ReentrantLock getLock() {
//        String normalizedPath;
//        try {
//            // 标准化路径，处理相对路径/绝对路径差异
//            normalizedPath = new File(filePath).getCanonicalPath();
//        } catch (IOException e) {
//            normalizedPath = filePath;
//        }
//        // 不存在则创建锁，确保线程安全
//        return PATH_LOCKS.computeIfAbsent(normalizedPath, k -> new ReentrantLock());
//    }
//
//    /**
//     * 处理HttpRequestResponse数据，转换为JSONObject
//     * 字段包含：reqmethod, reqUrl, reqHeaders, reqBody, respStatusCode, respHeaders, respBody, timestamp
//     */
//    private JSONObject processHttpData(HttpRequestResponse rr) {
//        JSONObject data = new JSONObject();
//        HttpRequest request = rr.request();
//        HttpResponse response = rr.response();
//
//        // 构造请求头字符串（强制转义）
//        StringBuilder reqHeadersStr = new StringBuilder();
//        if (request.headers() != null) {
//            for (HttpHeader header : request.headers()) {
//                String name = Objects.toString(header.name(), "");
//                String value = Objects.toString(header.value(), "");
//                reqHeadersStr.append(name).append(": ").append(JSONObject.toJSONString(value)).append("; ");
//            }
//        }
//
//        // 构造响应头字符串（强制转义）
//        StringBuilder respHeadersStr = new StringBuilder();
//        if (response != null && response.headers() != null) {
//            for (HttpHeader header : response.headers()) {
//                String name = Objects.toString(header.name(), "");
//                String value = Objects.toString(header.value(), "");
//                respHeadersStr.append(name).append(": ").append(JSONObject.toJSONString(value)).append("; ");
//            }
//        }
//
//        // 请求体处理（转义）
//        String reqBody = request.body().length() > 0 ? request.bodyToString() : "";
//
//        // 响应相关字段初始化
//        int statusCode = 0;
//        String respHeaders = "";
//        String respBody = "";
//        if (response != null) {
//            statusCode = response.statusCode();
//            respHeaders = respHeadersStr.toString().trim();
//            respBody = response.body().length() > 0 ? response.bodyToString() : "";
//        }
//
//        // 所有字段JSON转义存储
//        data.put("reqmethod", request.method());
//        data.put("reqUrl", request.url());
//        data.put("reqHeaders", reqHeadersStr.toString().trim());
//        data.put("reqBody", JSONObject.toJSONString(reqBody));
//        data.put("respStatusCode", statusCode);
//        data.put("respHeaders", respHeaders);
//        data.put("respBody", JSONObject.toJSONString(respBody));
//        data.put("timestamp", System.currentTimeMillis());
//
//        return data;
//    }
//
//    /**
//     * 将处理后的HTTP数据追加到当前实例对应的JSON文件（List<JSONArray>格式）
//     * 每次追加会读取原有数据，添加新元素后整体写入（保持JSON格式完整）
//     *
//     * @param rr       待处理的HTTP请求响应数据
//     * @throws IOException   目录创建失败或文件读写错误
//     * @throws JSONException JSON格式错误（如文件内容损坏）
//     */
//    public void appendHttpData(HttpRequestResponse rr) throws IOException, JSONException {
//        ReentrantLock lock = getLock();
//        lock.lock(); // 加锁，确保读写原子性
//        try {
//            // 确保目录存在
//            File file = new File(filePath);
//            File parentDir = file.getParentFile();
//            if (parentDir != null && !parentDir.exists()) {
//                boolean dirCreated = parentDir.mkdirs();
//                if (!dirCreated) {
//                    throw new IOException("无法创建目录: " + parentDir.getAbsolutePath());
//                }
//            }
//
//            // 读取现有数据（若文件不存在则初始化空列表）
//            List<JSONObject> dataList;
//            if (file.exists() && file.length() > 0) {
//                // 读取文件内容并解析为List<JSONObject>
//                String jsonContent = Files.readString(Paths.get(filePath), StandardCharsets.UTF_8);
//                dataList = JSON.parseArray(jsonContent, JSONObject.class);
//            } else {
//                dataList = new ArrayList<>();
//            }
//
//            // 处理新数据并追加到列表
//            JSONObject newData = processHttpData(rr);
//            dataList.add(newData);
//
//            // 美化格式写入文件（覆盖原有内容，保持JSON数组完整性）
//            String prettyJson = JSON.toJSONString(dataList, JSONWriter.Feature.PrettyFormat);
//            Files.writeString(Paths.get(filePath), prettyJson, StandardCharsets.UTF_8);
//
//        } finally {
//            lock.unlock(); // 确保锁释放，避免死锁
//        }
//    }
//
//    /**
//     * 清理当前实例文件路径的锁（一般无需手动调用）
//     */
//    public void cleanLock() {
//        try {
//            String normalizedPath = new File(filePath).getCanonicalPath();
//            PATH_LOCKS.remove(normalizedPath);
//        } catch (IOException e) {
//            PATH_LOCKS.remove(filePath);
//        }
//    }
//}