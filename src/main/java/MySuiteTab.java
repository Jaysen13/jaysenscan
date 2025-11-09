import burp.api.montoya.MontoyaApi;
import burp.api.montoya.collaborator.CollaboratorClient;
import burp.api.montoya.collaborator.PayloadOption;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.repeater.Repeater;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.*;
import java.util.ArrayList;
import java.util.List;

public class MySuiteTab {
    private final JPanel panel;
    private final JTable requestTable;
    private final DefaultTableModel tableModel;
    private final JTextArea requestArea;
    private final JTextArea responseArea;
    private int requestIndex = 1;
    private final List<String> requestContents = new ArrayList<>();
    private final List<String> responseContents = new ArrayList<>();
    private final JSplitPane mainSplitPane;
    private final JSplitPane rightSplitPane;
    private final JScrollPane requestScrollPane;
    private final JScrollPane responseScrollPane;
    private final List<HttpRequestResponse> requestResponses = new ArrayList<>();
    private final MontoyaApi montoyaApi;

    // 新增：配置面板相关组件
    private final JPanel configPanel; // 配置内容面板（默认隐藏）
    private boolean configExpanded = false; // 配置面板展开状态

    public MySuiteTab(MontoyaApi montoyaApi) {
        this.montoyaApi = montoyaApi;
        panel = new JPanel();
        panel.setLayout(new BorderLayout());

        // ==============================================
        // 顶部区域：新增配置按钮 + 配置面板 + 原有清空按钮
        // ==============================================
        JPanel topContainer = new JPanel(new BorderLayout());

        // 左侧：配置按钮
        JPanel configButtonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton configBtn = new JButton("配置");
        configBtn.addActionListener(e -> toggleConfigPanel()); // 点击切换展开/折叠
        configButtonPanel.add(configBtn);
        topContainer.add(configButtonPanel, BorderLayout.WEST);

        // 右侧：原有清空按钮
        JPanel topRightPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton clearBtn = new JButton("清空所有数据");
        clearBtn.addActionListener(e -> clearAllData());
        topRightPanel.add(clearBtn);
        topContainer.add(topRightPanel, BorderLayout.EAST);

        // 新增：可折叠的配置面板（默认隐藏）
        configPanel = createConfigPanel();
        configPanel.setVisible(false); // 初始隐藏

        // 将顶部按钮区和配置面板添加到主面板顶部
        JPanel northPanel = new JPanel(new BorderLayout());
        northPanel.add(topContainer, BorderLayout.NORTH);
        northPanel.add(configPanel, BorderLayout.CENTER);
        panel.add(northPanel, BorderLayout.NORTH);

        // ==============================================
        // 原有中间区域：表格和请求响应展示（保持不变）
        // ==============================================
        mainSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);

        // 左半边表格
        String[] columnNames = {"序号", "请求域名", "请求方法", "URL", "响应码"};
        tableModel = new DefaultTableModel(columnNames, 0);
        requestTable = new JTable(tableModel) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        initTableRightMenu();
        initTableShortcut();

        JScrollPane tableScrollPane = new JScrollPane(requestTable);
        JPanel leftPanel = new JPanel(new BorderLayout());
        leftPanel.add(tableScrollPane, BorderLayout.CENTER);

        // 右半边请求响应
        JPanel rightPanel = new JPanel(new BorderLayout());
        rightSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);

        requestArea = new JTextArea(10, 30);
        requestArea.setEditable(false);
        requestScrollPane = new JScrollPane(requestArea);
        rightSplitPane.setTopComponent(requestScrollPane);

        responseArea = new JTextArea(10, 30);
        responseArea.setEditable(false);
        responseScrollPane = new JScrollPane(responseArea);
        rightSplitPane.setBottomComponent(responseScrollPane);

        rightPanel.add(rightSplitPane, BorderLayout.CENTER);

        mainSplitPane.setLeftComponent(leftPanel);
        mainSplitPane.setRightComponent(rightPanel);
        panel.add(mainSplitPane, BorderLayout.CENTER);

        // 表格点击事件（保持不变）
        requestTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int selectedRow = requestTable.getSelectedRow();
                if (selectedRow != -1 && selectedRow < requestContents.size() && selectedRow < responseContents.size()) {
                    requestArea.setText(requestContents.get(selectedRow));
                    responseArea.setText(responseContents.get(selectedRow));
                    refreshScrollBar();
                }
            }
        });

        // 分割面板比例设置（保持不变）
        panel.addComponentListener(new ComponentAdapter() {
            @Override
            public void componentShown(ComponentEvent e) {
                super.componentShown(e);
                mainSplitPane.setDividerLocation(0.5);
                rightSplitPane.setDividerLocation(0.5);
            }
        });

    }

    // ==============================================
    // 新增：创建配置面板内容（DNSlog平台选择等）
    // ==============================================
    private JPanel createConfigPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 10, 5, 10);
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;

        // 1. DNSlog平台选择
        gbc.gridx = 0;
        gbc.gridy = 0;
        panel.add(new JLabel("DNSlog平台:"), gbc);
        gbc.gridx = 1;
        JComboBox<String> platformSelector = new JComboBox<>(new String[]{"collaborator", "ceye"});
        platformSelector.setSelectedItem(DnslogConfig.getInstance().platform);
        panel.add(platformSelector, gbc);

        // 2. Collaborator域名（新增“自动生成”按钮）
        gbc.gridx = 0;
        gbc.gridy = 1;
        panel.add(new JLabel("Collaborator域名:"), gbc);

        JPanel collabDomainPanel = new JPanel(new BorderLayout());
        JTextField collabDomainField = new JTextField(25);
        collabDomainField.setText(DnslogConfig.getInstance().collaboratorDomain);
        collabDomainPanel.add(collabDomainField, BorderLayout.CENTER);

        JButton generateBtn = new JButton("自动生成");
        generateBtn.addActionListener(e -> {
            // 生成域名
            String collaboratorDomain = CheckDnslogResult.createCollaborator(montoyaApi);
            collabDomainField.setText(collaboratorDomain);
        });
        collabDomainPanel.add(generateBtn, BorderLayout.EAST);

        gbc.gridx = 1;
        panel.add(collabDomainPanel, gbc);

        // 3. CEYE APIKey（仅CEYE显示）
        gbc.gridx = 0;
        gbc.gridy = 2;
        JLabel apiKeyLabel = new JLabel("CEYE APIKey:");
        panel.add(apiKeyLabel, gbc);
        gbc.gridx = 1;
        JTextField ceyeApiKeyField = new JTextField(30);
        ceyeApiKeyField.setText(DnslogConfig.getInstance().ceyeApiKey);
        panel.add(ceyeApiKeyField, gbc);

        // 4. CEYE APIDomain（仅CEYE显示）
        gbc.gridx = 0;
        gbc.gridy = 3;
        JLabel apiDomainLabel = new JLabel("CEYE APIDomain:");
        panel.add(apiDomainLabel, gbc);
        gbc.gridx = 1;
        JTextField ceyeApiDomainField = new JTextField(30);
        ceyeApiDomainField.setText(DnslogConfig.getInstance().ceyeApiDomain);
        panel.add(ceyeApiDomainField, gbc);

        // 5. 目标域名（始终显示）
        gbc.gridx = 0;
        gbc.gridy = 4;
        panel.add(new JLabel("目标域名:"), gbc);
        gbc.gridx = 1;
        JTextField targetDomainField = new JTextField(30);
        targetDomainField.setText(DnslogConfig.getInstance().targetDomain);
        panel.add(targetDomainField, gbc);

        // 6. 保存配置按钮（跨列居中）
        gbc.gridx = 0;
        gbc.gridy = 5;
        gbc.gridwidth = 2;
        gbc.anchor = GridBagConstraints.CENTER;
        JButton saveBtn = new JButton("保存配置");
        saveBtn.addActionListener(e -> {
            // 获取用户输入的配置值
            String selectedPlatform = (String) platformSelector.getSelectedItem();
            String collabDomain = collabDomainField.getText().trim();
            String ceyeKey = ceyeApiKeyField.getText().trim();
            String ceyeDomain = ceyeApiDomainField.getText().trim();
            String targetDomain = targetDomainField.getText().trim();

            // 配置验证（根据平台类型检查必填项）
            StringBuilder errorMsg = new StringBuilder();
            if ("ceye".equals(selectedPlatform)) {
                if (ceyeKey.isEmpty()) {
                    errorMsg.append("CEYE APIKey不能为空\n");
                }
                if (ceyeDomain.isEmpty()) {
                    errorMsg.append("CEYE APIDomain不能为空\n");
                }
            }
            // 目标域名可选验证（根据你的业务需求决定是否必填）
            if (targetDomain.isEmpty()) {
                errorMsg.append("目标域名建议填写（可留空）\n");
            }

            // 验证失败时提示错误
            if (errorMsg.length() > 0) {
                JOptionPane.showMessageDialog(
                        panel,
                        "配置不完整：\n" + errorMsg.toString(),
                        "保存失败",
                        JOptionPane.ERROR_MESSAGE
                );
                return;
            }

            // 验证通过，保存配置到单例
            DnslogConfig config = DnslogConfig.getInstance();
            config.platform = selectedPlatform;
            config.collaboratorDomain = collabDomain;
            config.ceyeApiKey = ceyeKey;
            config.ceyeApiDomain = ceyeDomain;
            config.targetDomain = targetDomain;
            if (selectedPlatform.equals("ceye")) {
                config.donlogType = Config.DnslogType.CEYE;
            }else{
                config.donlogType = Config.DnslogType.COLLABORATOR;
            }

            // 持久化到本地文件
            try {
                config.save(); // 调用DnslogConfig中的save方法写入文件
                JOptionPane.showMessageDialog(
                        panel,
                        "配置保存成功！\n" +
                                "平台：" + selectedPlatform + "\n" +
                                (selectedPlatform.equals("ceye") ?
                                        "CEYE域名：" + ceyeDomain :
                                        "Collaborator域名：" + (collabDomain.isEmpty() ? "自动生成" : collabDomain)),
                        "保存成功",
                        JOptionPane.INFORMATION_MESSAGE
                );
                montoyaApi.logging().logToOutput("配置已保存到本地文件");
            } catch (Exception ex) {
                // 捕获文件写入异常（如权限不足）
                JOptionPane.showMessageDialog(
                        panel,
                        "保存配置失败：\n" + ex.getMessage(),
                        "保存错误",
                        JOptionPane.ERROR_MESSAGE
                );
                montoyaApi.logging().logToError("配置保存失败：" + ex.getMessage());
            }
        });
        panel.add(saveBtn, gbc);

        // 平台切换时控制CEYE项显隐
        platformSelector.addItemListener(e -> {
            boolean isCeye = "ceye".equals(e.getItem());
            apiKeyLabel.setVisible(isCeye);
            ceyeApiKeyField.setVisible(isCeye);
            apiDomainLabel.setVisible(isCeye);
            ceyeApiDomainField.setVisible(isCeye);
            collabDomainField.setEnabled(!isCeye);
            generateBtn.setEnabled(!isCeye); // 按钮随输入框禁用状态同步
        });

        // 初始状态设置
        boolean isCeyeDefault = "ceye".equals(DnslogConfig.getInstance().platform);
        apiKeyLabel.setVisible(isCeyeDefault);
        ceyeApiKeyField.setVisible(isCeyeDefault);
        apiDomainLabel.setVisible(isCeyeDefault);
        ceyeApiDomainField.setVisible(isCeyeDefault);
        collabDomainField.setEnabled(!isCeyeDefault);
        generateBtn.setEnabled(!isCeyeDefault); // 初始按钮状态

        panel.setBorder(BorderFactory.createTitledBorder("DNSlog配置"));
        return panel;
    }

    // ==============================================
    // 新增：切换配置面板展开/折叠状态
    // ==============================================
    private void toggleConfigPanel() {
        configExpanded = !configExpanded;
        configPanel.setVisible(configExpanded);
        // 刷新布局
        panel.revalidate();
        panel.repaint();
    }

    // ==============================================
    // 原有功能代码（保持不变）
    // ==============================================
    private void initTableRightMenu() {
        JPopupMenu rightMenu = new JPopupMenu();

        JMenuItem deleteItem = new JMenuItem("删除选中行");
        deleteItem.addActionListener(e -> {
            int selectedRow = requestTable.getSelectedRow();
            if (selectedRow != -1) {
                tableModel.removeRow(selectedRow);
                requestContents.remove(selectedRow);
                responseContents.remove(selectedRow);
                requestResponses.remove(selectedRow);
                if (requestTable.getSelectedRow() == -1) {
                    requestArea.setText("");
                    responseArea.setText("");
                }
            }
        });
        rightMenu.add(deleteItem);

        JMenuItem sendToRepeaterItem = new JMenuItem("发送到重放器");
        sendToRepeaterItem.addActionListener(e -> sendSelectedToRepeater());
        rightMenu.add(sendToRepeaterItem);

        requestTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseReleased(MouseEvent e) {
                if (SwingUtilities.isRightMouseButton(e)) {
                    int selectedRow = requestTable.rowAtPoint(e.getPoint());
                    if (selectedRow != -1 && !requestTable.isRowSelected(selectedRow)) {
                        requestTable.setRowSelectionInterval(selectedRow, selectedRow);
                    }
                    if (requestTable.getSelectedRow() != -1) {
                        rightMenu.show(requestTable, e.getX(), e.getY());
                    }
                }
            }
        });
    }

    private void initTableShortcut() {
        requestTable.addKeyListener(new KeyAdapter() {
            @Override
            public void keyPressed(KeyEvent e) {
                if (e.isControlDown() && e.getKeyCode() == KeyEvent.VK_R) {
                    sendSelectedToRepeater();
                }
            }
        });
    }

    private void sendSelectedToRepeater() {
        int selectedRow = requestTable.getSelectedRow();
        if (selectedRow == -1) {
            JOptionPane.showMessageDialog(panel, "请先选中一行数据！", "提示", JOptionPane.WARNING_MESSAGE);
            return;
        }
        if (selectedRow >= requestResponses.size()) {
            JOptionPane.showMessageDialog(panel, "数据列表索引异常，请尝试清空后重新添加数据！", "提示", JOptionPane.ERROR_MESSAGE);
            return;
        }
        HttpRequestResponse rr = requestResponses.get(selectedRow);
        Repeater repeater = montoyaApi.repeater();
        repeater.sendToRepeater(rr.request());
    }

    private void clearAllData() {
        tableModel.setRowCount(0);
        requestContents.clear();
        responseContents.clear();
        requestResponses.clear();
        requestIndex = 1;
        requestArea.setText("");
        responseArea.setText("");
    }

    public void addRequestInfo(HttpRequestResponse rr) {
        String domain = rr.request().headerValue("Host");
        String method = rr.request().method();
        String path = rr.request().path();
        int statusCode = rr.response().statusCode();
        String request = rr.request().toString();
        String response = rr.response().toString();
        Object[] rowData = {requestIndex++, domain, method, path, statusCode};
        tableModel.addRow(rowData);
        requestContents.add(request);
        responseContents.add(response);
        requestResponses.add(rr);

        if (tableModel.getRowCount() == 1) {
            requestArea.setText(request);
            responseArea.setText(response);
            refreshScrollBar();
        }
    }

    public Component getUiComponent() {
        return panel;
    }

    private void refreshScrollBar() {
        SwingUtilities.invokeLater(() -> {
            responseArea.revalidate();
            responseArea.repaint();
            requestScrollPane.getVerticalScrollBar().setValue(0);
            responseScrollPane.getVerticalScrollBar().setValue(0);
            requestScrollPane.getHorizontalScrollBar().setValue(0);
            responseScrollPane.getHorizontalScrollBar().setValue(0);
        });
    }
}

