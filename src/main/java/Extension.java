import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

public class Extension implements BurpExtension {
    private static final int CORE_POOL_SIZE = 28;
    private static final int MAX_POOL_SIZE = 112;
    private static final int QUEUE_CAPACITY = 2000;
    private static final long KEEP_ALIVE_TIME = 60L;
    private PluginTaskExecutor executor;
    @Override
    public void initialize(MontoyaApi montoyaApi) {
        montoyaApi.extension().setName("JaySenScan");
        montoyaApi.logging().logToOutput("""
                    _                                                                      __      __  __        ___ \s
                   (_)                                                                     \\ \\    / / /_ |      / _ \\\s
                    _    __ _   _   _   ___    ___   _ __    ___    ___    __ _   _ __      \\ \\  / /   | |     | | | |
                   | |  / _` | | | | | / __|  / _ \\ | '_ \\  / __|  / __|  / _` | | '_ \\      \\ \\/ /    | |     | | | |
                   | | | (_| | | |_| | \\__ \\ |  __/ | | | | \\__ \\ | (__  | (_| | | | | |      \\  /     | |  _  | |_| |
                   | |  \\__,_|  \\__, | |___/  \\___| |_| |_| |___/  \\___|  \\__,_| |_| |_|       \\/      |_| (_)  \\___/\s
                  _/ |           __/ |                                                                               \s
                 |__/           |___/                                                                                \s
                """);
        DnslogConfig.getInstance();
        // 初始化自定义线程池
        this.executor = new PluginTaskExecutor(
                CORE_POOL_SIZE,
                MAX_POOL_SIZE,
                KEEP_ALIVE_TIME,
                QUEUE_CAPACITY,
                500,
                montoyaApi
        );

        // 注册标签页面
        MySuiteTab mySuiteTab = new MySuiteTab(montoyaApi);
        montoyaApi.userInterface().registerSuiteTab("JaySenScan", mySuiteTab.getUiComponent());
        // 注册菜单
        montoyaApi.userInterface().registerContextMenuItemsProvider(new MyMenu(montoyaApi, mySuiteTab, executor));
        // 注册HTTP监听器
        montoyaApi.http().registerHttpHandler(new MyHttpHandler(montoyaApi, mySuiteTab, executor));
        // 初始化 CheckDnslogResult
        CheckDnslogResult.initialize(montoyaApi, mySuiteTab);
        // 卸载关闭线程
        montoyaApi.extension().registerUnloadingHandler(this::unload);
    }

    private void unload() {
        // 关闭批量检查的定时任务
        CheckDnslogResult.getInstance().shutdown();
        // 关闭其他线程池（如扫描线程池）
        executor.shutdown();
    }
}