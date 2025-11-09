import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import com.alibaba.fastjson2.JSONArray;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

public class MyMenu implements ContextMenuItemsProvider {
    private final MontoyaApi montoyaApi;
    private final MySuiteTab mySuiteTab;
    private final PluginTaskExecutor executor;
    private final Scan scan;
    public MyMenu(MontoyaApi montoyaApi, MySuiteTab mySuiteTab, PluginTaskExecutor executor) {
        this.montoyaApi = montoyaApi;
        this.mySuiteTab = mySuiteTab;
        this.scan = new Scan(montoyaApi,mySuiteTab,executor); // 初始化Scan实例
        this.executor = executor;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> menuItems = new ArrayList<>();
        // 1. 获取选中的“请求-响应对”列表
        List<HttpRequestResponse> requestResponses = event.selectedRequestResponses();
        if (requestResponses.isEmpty()) {
            return menuItems; // 没有选中内容，直接返回
        }
        // 2. 创建右键菜单项
        JMenuItem myMenuItem = new JMenuItem("1、判断是否为json格式请求");
        myMenuItem.addActionListener(e -> {
            // 3. 遍历“请求-响应对”，
            for (HttpRequestResponse rr : requestResponses) {
                if(!IsJsonRequest.isJsonRequest(rr).isEmpty()) {
                    // 将其添加到标签页
                    this.mySuiteTab.addRequestInfo(rr);
                    montoyaApi.logging().logToOutput(rr.request().url() + "请求为JSON格式传输");
                }
                else {
                    montoyaApi.logging().logToError(rr.request().url() + "请求非JSON格式传输");
                }
            }
        });
        // 创建第2个菜单选项
        JMenuItem fastJsonScanMenuItem = new JMenuItem("2、发起fastjson漏洞探测");
        ArrayList<HttpRequest> fastJsonRequest = new ArrayList<>();
        ArrayList<List<JsonData>> fastJsonData = new ArrayList<>();
        fastJsonScanMenuItem.addActionListener(e1 -> {
            for (HttpRequestResponse rr : requestResponses) {
                // 提取json数据
                List<JsonData> jsonData = IsJsonRequest.isJsonRequest(rr);
                fastJsonData.add(jsonData);
                if(!jsonData.isEmpty()) {
                    fastJsonRequest.add(rr.request());
                }else {
                    JOptionPane.showMessageDialog(null,"该请求不是json传输格式","警告",JOptionPane.INFORMATION_MESSAGE);
                }
            }
            // 线程任务提交
            executor.submit(() -> {
                scan.fastJsonScan(fastJsonRequest,fastJsonData);
            });

        });
        menuItems.add(myMenuItem);
        menuItems.add(fastJsonScanMenuItem);
        return menuItems;
    }
}
