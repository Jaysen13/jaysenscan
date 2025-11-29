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
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.*;
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
 * 6. 缓存满100条自动写入，卸载前确保缓存写入
 */
public class SaveLogFile {
    private final String baseDir; // 日志根目录
    private final String prefix;  // 日志文件前缀
    private final long maxFileSize; // 单个文件最大大小（字节）
    private final int retainDays; // 日志保留天数
    private static final ConcurrentHashMap<String, ReentrantLock> PATH_LOCKS = new ConcurrentHashMap<>();
    private final List<HttpRequestResponse> attackReqresps; // 存储扫描结果缓存
    private final ScheduledExecutorService scheduler;
    private static final int BATCH_SIZE = 100; // 缓存阈值，满100条自动写入
    private final ReentrantLock cacheLock = new ReentrantLock(); // 缓存操作锁
    // 构造方法：可配置分割大小、保留天数等
    public SaveLogFile() {
        this.baseDir = DnslogConfig.getInstance().logPath + "/";
        this.prefix = "jaysenscanlog_" + LocalDate.now().format(DateTimeFormatter.ofPattern("yyyyMMdd")) + "_";
        this.maxFileSize = 100 * 1024 * 1024; // 100MB
        this.retainDays = DnslogConfig.getInstance().logRetentionDays;
        this.attackReqresps = new ArrayList<>();
        // 定时任务线程池（单线程即可，避免并发检查冲突）
        this.scheduler = Executors.newSingleThreadScheduledExecutor();
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

    // 将恶意请求日志添加入缓存，满100条自动写入
    public void addToBatch(HttpRequestResponse rr) {
        cacheLock.lock();
        try {
            attackReqresps.add(rr);
            // 达到阈值时触发批量写入
            if (attackReqresps.size() >= BATCH_SIZE) {
                // 使用后台线程写入，避免阻塞调用方
                scheduler.submit(this::flushCache);
            }
        } finally {
            cacheLock.unlock();
        }
    }

    // 强制将缓存中的日志写入文件
    public void flushCache() {
        List<HttpRequestResponse> toWrite = new ArrayList<>();
        // 取出当前缓存中的所有数据（原子操作）
        cacheLock.lock();
        try {
            if (!attackReqresps.isEmpty()) {
                toWrite.addAll(attackReqresps);
                attackReqresps.clear(); // 清空缓存
            }
        } finally {
            cacheLock.unlock();
        }

        // 批量写入文件
        if (!toWrite.isEmpty()) {
            try {
                String filePath = getCurrentFilePath();
                ReentrantLock fileLock = getLock(filePath);
                fileLock.lock();
                try (BufferedWriter writer = new BufferedWriter(
                        new OutputStreamWriter(
                                new GZIPOutputStream(
                                        new FileOutputStream(filePath, true)), // 追加模式
                                StandardCharsets.UTF_8))) {

                    for (HttpRequestResponse rr : toWrite) {
                        JSONObject data = processHttpData(rr);
                        String jsonLine = JSON.toJSONString(data);
                        writer.write(jsonLine);
                        writer.newLine();
                    }
                } finally {
                    fileLock.unlock();
                }
                // 写入成功后检查文件大小，必要时触发分割（由getCurrentFilePath自动处理）
            } catch (IOException e) {
                // 写入失败时将数据放回缓存（避免丢失）
                cacheLock.lock();
                try {
                    attackReqresps.addAll(0, toWrite); // 放前面优先处理
                } finally {
                    cacheLock.unlock();
                }
                System.err.println("批量写入日志失败：" + e.getMessage());
            }
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

    // 追加单条数据到日志文件（保持原有接口兼容）
//    public void appendHttpData(HttpRequestResponse rr) throws IOException {
//        String filePath = getCurrentFilePath();
//        ReentrantLock lock = getLock(filePath);
//        lock.lock();
//        try (BufferedWriter writer = new BufferedWriter(
//                new OutputStreamWriter(
//                        new GZIPOutputStream(
//                                new FileOutputStream(filePath, true)), // 追加模式
//                        StandardCharsets.UTF_8))) {
//
//            JSONObject data = processHttpData(rr);
//            String jsonLine = JSON.toJSONString(data);
//            writer.write(jsonLine);
//            writer.newLine();
//
//        } finally {
//            lock.unlock();
//        }
//    }

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

    // 清理资源（在卸载前调用）
    public void cleanUp() {
        // 1. 确保缓存中剩余日志全部写入
        flushCache();
        // 2. 关闭定时任务线程池
        scheduler.shutdown();
        try {
            // 等待线程池关闭，最多等待5秒
            if (!scheduler.awaitTermination(5, TimeUnit.SECONDS)) {
                scheduler.shutdownNow();
            }
        } catch (InterruptedException e) {
            scheduler.shutdownNow();
        }
        // 3. 清理文件锁
        cleanLock();
    }

    // 清理锁
    public void cleanLock() {
        try {
            String normalizedPath = new File(baseDir).getCanonicalPath();
            PATH_LOCKS.remove(normalizedPath);
        } catch (IOException e) {
            PATH_LOCKS.remove(baseDir);
        }
    }
}