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
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import burp.api.montoya.MontoyaApi;

public class PluginTaskExecutor {
    private final ThreadPoolExecutor executor;
    private final MontoyaApi montoyaApi;
    private final TokenBucket rateLimiter;
    private final int maxQueueSize;

    public PluginTaskExecutor(
            int corePoolSize,
            int maxPoolSize,
            long keepAliveTimeSeconds,
            int queueCapacity,
            double qps,
            MontoyaApi montoyaApi) {

        this.montoyaApi = montoyaApi;
        this.maxQueueSize = queueCapacity;
        this.rateLimiter = new TokenBucket(qps);

        // 【修复1：正确实现ThreadFactory，解决线程构造器错误】
        ThreadFactory threadFactory = new ThreadFactory() {
            private final AtomicInteger threadNumber = new AtomicInteger(1); // 线程编号生成器

            @Override
            public Thread newThread(Runnable r) {
                // 正确构造线程：传入任务Runnable和线程名称
                Thread t = new Thread(r, "burp-plugin-worker-" + threadNumber.getAndIncrement());
                t.setDaemon(true); // 设置为守护线程
                return t;
            }
        };

        // 等待策略
        RejectedExecutionHandler rejectionHandler = new ThreadPoolExecutor.CallerRunsPolicy();

        // 初始化线程池（保持不变）
        this.executor = new ThreadPoolExecutor(
                corePoolSize,
                maxPoolSize,
                keepAliveTimeSeconds,
                TimeUnit.SECONDS,
                new LinkedBlockingQueue<>(queueCapacity),
                threadFactory,
                rejectionHandler
        );

        startPoolMonitor();
    }

    public void submit(Runnable task) {
        try {
            rateLimiter.acquire();
            executor.submit(() -> {
                try {
                    task.run();
                } catch (Exception e) {
                    montoyaApi.logging().logToError("任务异常: " + e.getMessage());
                }
            });
        } catch (Exception e) {
            montoyaApi.logging().logToError("提交任务失败: " + e.getMessage());
        }
    }

    // 自定义令牌桶（保持不变）
    private static class TokenBucket {
        private final double qps;
        private final long maxBurstTokens;
        private double availableTokens;
        private long lastRefillTime;

        public TokenBucket(double qps) {
            this.qps = qps;
            this.maxBurstTokens = (long) Math.ceil(qps);
            this.availableTokens = maxBurstTokens;
            this.lastRefillTime = System.nanoTime();
        }

        public synchronized void acquire() throws InterruptedException {
            refill();

            if (availableTokens < 1) {
                long waitNanos = (long) ((1 - availableTokens) * 1_000_000_000 / qps);
                long waitMillis = (waitNanos + 999_999) / 1_000_000;
                Thread.sleep(waitMillis);
                refill();
            }

            availableTokens -= 1;
        }

        private void refill() {
            long now = System.nanoTime();
            long elapsedNanos = now - lastRefillTime;
            if (elapsedNanos <= 0) {
                return;
            }

            double newTokens = (elapsedNanos / 1_000_000_000.0) * qps;
            availableTokens = Math.min(availableTokens + newTokens, maxBurstTokens);
            lastRefillTime = now;
        }
    }

    // 线程池监控（保持不变）
    private void startPoolMonitor() {
        ScheduledExecutorService monitorExecutor = Executors.newSingleThreadScheduledExecutor();
        monitorExecutor.scheduleAtFixedRate(() -> {
            int activeThreads = executor.getActiveCount();
            int queueSize = executor.getQueue().size();
            long completedTasks = executor.getCompletedTaskCount();
            double queueUsage = (double) queueSize / maxQueueSize * 100;

//            montoyaApi.logging().logToOutput(String.format(
//                    "线程池监控：活跃线程=%d，排队任务=%d（%.1f%%），已完成任务=%d",
//                    activeThreads, queueSize, queueUsage, completedTasks
//            ));

//            if (queueUsage > 80) {
//                montoyaApi.logging().logToOutput("警告：队列即将满负荷，请调整参数");
//            }
        }, 0, 30, TimeUnit.SECONDS);

        Runtime.getRuntime().addShutdownHook(new Thread(monitorExecutor::shutdownNow));
    }

    public void shutdown() {
        if (!executor.isShutdown()) {
            executor.shutdown();
            try {
                if (!executor.awaitTermination(60, TimeUnit.SECONDS)) {
                    executor.shutdownNow();
                }
            } catch (InterruptedException e) {
                executor.shutdownNow();
            }
            montoyaApi.logging().logToOutput("线程池已关闭，完成任务：" + executor.getCompletedTaskCount());
        }
    }
}