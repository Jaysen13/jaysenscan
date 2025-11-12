import burp.api.montoya.MontoyaApi;
import burp.api.montoya.collaborator.CollaboratorClient;
import burp.api.montoya.collaborator.PayloadOption;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.repeater.Repeater;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.*;
import java.io.File;
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
    private DnslogConfig dnslogConfig;
    // 配置面板相关组件
    private final JPanel configPanel; // 配置内容面板（默认隐藏）
    private boolean configExpanded = false; // 配置面板展开状态

    public MySuiteTab(MontoyaApi montoyaApi) {
        this.montoyaApi = montoyaApi;
        panel = new JPanel();
        panel.setLayout(new BorderLayout());
        this.dnslogConfig = DnslogConfig.getInstance();

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

    private JPanel createConfigPanel() {
        // 主配置面板（三栏布局）
        JPanel mainConfigPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.fill = GridBagConstraints.BOTH;
        gbc.weighty = 1.0; // 垂直方向占满空间


        // ==============================================
        // 左侧区域：DNSlog配置（原配置内容）
        // ==============================================
        JPanel leftPanel = new JPanel(new GridBagLayout());
        leftPanel.setBorder(BorderFactory.createTitledBorder("DNSlog配置"));
        GridBagConstraints leftGbc = new GridBagConstraints();
        leftGbc.insets = new Insets(5, 5, 5, 5);
        leftGbc.anchor = GridBagConstraints.WEST;
        leftGbc.fill = GridBagConstraints.HORIZONTAL;
        leftGbc.gridx = 0;
        leftGbc.gridwidth = 2; // 统一占2列，避免布局错乱

        // 1. DNSlog平台选择
        leftGbc.gridy = 0;
        leftPanel.add(new JLabel("DNSlog平台:"), leftGbc);
        leftGbc.gridy++;
        JComboBox<String> platformSelector = new JComboBox<>(new String[]{"collaborator", "ceye"});
        platformSelector.setSelectedItem(dnslogConfig.platform);
        leftPanel.add(platformSelector, leftGbc);

        // 2. Collaborator域名 + 自动生成按钮
        leftGbc.gridy++;
        leftPanel.add(new JLabel("Collaborator域名:"), leftGbc);
        leftGbc.gridy++;
        JPanel collabDomainPanel = new JPanel(new BorderLayout());
        JTextField collabDomainField = new JTextField(20);
        collabDomainField.setText(dnslogConfig.collaboratorDomain);
        collabDomainPanel.add(collabDomainField, BorderLayout.CENTER);
        JButton generateBtn = new JButton("自动生成");
        generateBtn.addActionListener(e -> {
            String collaboratorDomain = CheckDnslogResult.createCollaborator(montoyaApi);
            collabDomainField.setText(collaboratorDomain);
            // 同步更新配置实例中的值
            dnslogConfig.collaboratorDomain = collaboratorDomain;
            dnslogConfig.save();
        });
        collabDomainPanel.add(generateBtn, BorderLayout.EAST);
        leftPanel.add(collabDomainPanel, leftGbc);
        //插件加载时自动检测并生成Collaborator域名（如果未配置）
        if (dnslogConfig.domainToClientMap.get(dnslogConfig.collaboratorDomain) == null || dnslogConfig.collaboratorDomain.isEmpty()) {
            // 自动生成域名
            String autoGeneratedDomain = CheckDnslogResult.createCollaborator(montoyaApi);
            // 更新UI和配置
            collabDomainField.setText(autoGeneratedDomain);
            dnslogConfig.collaboratorDomain = autoGeneratedDomain;
            dnslogConfig.save();
            // 日志提示
            montoyaApi.logging().logToOutput("检测到未正确配置Collaborator域名，已自动生成");
        }

        // 3. CEYE APIKey（仅CEYE显示）
        leftGbc.gridy++;
        JLabel apiKeyLabel = new JLabel("CEYE APIKey:");
        leftPanel.add(apiKeyLabel, leftGbc);
        leftGbc.gridy++;
        JTextField ceyeApiKeyField = new JTextField(20);
        ceyeApiKeyField.setText(dnslogConfig.ceyeApiKey);
        leftPanel.add(ceyeApiKeyField, leftGbc);

        // 4. CEYE APIDomain（仅CEYE显示）
        leftGbc.gridy++;
        JLabel apiDomainLabel = new JLabel("CEYE APIDomain:");
        leftPanel.add(apiDomainLabel, leftGbc);
        leftGbc.gridy++;
        JTextField ceyeApiDomainField = new JTextField(20);
        ceyeApiDomainField.setText(dnslogConfig.ceyeApiDomain);
        leftPanel.add(ceyeApiDomainField, leftGbc);

        // 5. 目标域名
        leftGbc.gridy++;
        leftPanel.add(new JLabel("目标域名:"), leftGbc);
        leftGbc.gridy++;
        JTextField targetDomainField = new JTextField(20);
        targetDomainField.setText(dnslogConfig.targetDomain);
        leftPanel.add(targetDomainField, leftGbc);

        // 平台切换时控制CEYE项显隐（复用原逻辑）
        platformSelector.addItemListener(e -> {
            boolean isCeye = "ceye".equals(e.getItem());
            apiKeyLabel.setVisible(isCeye);
            ceyeApiKeyField.setVisible(isCeye);
            apiDomainLabel.setVisible(isCeye);
            ceyeApiDomainField.setVisible(isCeye);
            collabDomainField.setEnabled(!isCeye);
            generateBtn.setEnabled(!isCeye);
        });
        boolean isCeyeDefault = "ceye".equals(dnslogConfig.platform);
        apiKeyLabel.setVisible(isCeyeDefault);
        ceyeApiKeyField.setVisible(isCeyeDefault);
        apiDomainLabel.setVisible(isCeyeDefault);
        ceyeApiDomainField.setVisible(isCeyeDefault);
        collabDomainField.setEnabled(!isCeyeDefault);
        generateBtn.setEnabled(!isCeyeDefault);


        // ==============================================
        // 中间区域：扫描选项勾选框（预留扩展）
        // ==============================================
        JPanel middlePanel = new JPanel(new GridBagLayout());
        middlePanel.setBorder(BorderFactory.createTitledBorder("扫描选项"));
        GridBagConstraints midGbc = new GridBagConstraints();
        midGbc.insets = new Insets(5, 5, 5, 5);
        midGbc.anchor = GridBagConstraints.WEST;
        midGbc.gridx = 0;
        midGbc.gridy = 0;
        midGbc.gridwidth = 1;

        // 1. FastJson扫描勾选框
        JCheckBox fastJsonCheck = new JCheckBox("FastJson扫描");
        fastJsonCheck.setSelected(dnslogConfig.fastJsonScanEnabled);
        middlePanel.add(fastJsonCheck, midGbc);

        // 2. Log4J扫描勾选框
        midGbc.gridy++;
        JCheckBox log4jCheck = new JCheckBox("Log4J扫描");
        log4jCheck.setSelected(dnslogConfig.log4jScanEnabled);
        middlePanel.add(log4jCheck, midGbc);

        // 3.Spring扫描勾选框
        midGbc.gridy++;
        JCheckBox springCheck = new JCheckBox("Spring扫描");
        springCheck.setSelected(dnslogConfig.springScanEnabled);
        middlePanel.add(springCheck, midGbc);
//
//        midGbc.gridy++;
//        JCheckBox reserveCheck2 = new JCheckBox("预留选项2");
//        middlePanel.add(reserveCheck2, midGbc);

        // 填充空白区域（让勾选框靠上显示）
        midGbc.gridy++;
        midGbc.weighty = 1.0; // 占满剩余垂直空间
        middlePanel.add(new JPanel(), midGbc);


        // ==============================================
        // 右侧区域：日志存储设置
        // ==============================================
        JPanel rightPanel = new JPanel(new GridBagLayout());
        rightPanel.setBorder(BorderFactory.createTitledBorder("日志设置"));
        GridBagConstraints rightGbc = new GridBagConstraints();
        rightGbc.insets = new Insets(5, 5, 5, 5);
        rightGbc.anchor = GridBagConstraints.WEST;
        rightGbc.fill = GridBagConstraints.HORIZONTAL;
        rightGbc.gridx = 0;
        rightGbc.gridwidth = 2;

        // 1. 是否启用日志保存（单选框）
        rightGbc.gridy = 0;
        JRadioButton enableLogRadio = new JRadioButton("启用日志保存");
        JRadioButton disableLogRadio = new JRadioButton("禁用日志保存");
        ButtonGroup logGroup = new ButtonGroup();
        logGroup.add(enableLogRadio);
        logGroup.add(disableLogRadio);
        enableLogRadio.setSelected(DnslogConfig.getInstance().logEnabled);

        // 用面板包裹单选框，横向排列
        JPanel logRadioPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        logRadioPanel.add(enableLogRadio);
        logRadioPanel.add(disableLogRadio);
        rightPanel.add(logRadioPanel, rightGbc);

        // 2. 日志存储位置输入框（先添加位置，再添加时间）
        rightGbc.gridy++;
        JLabel logPathLabel = new JLabel("日志存储位置:");
        rightPanel.add(logPathLabel, rightGbc);

        rightGbc.gridy++;
        JTextField logPathField = new JTextField(20);
        String defaultLogPath = DnslogConfig.getInstance().logPath;
        logPathField.setText(defaultLogPath);
        rightPanel.add(logPathField, rightGbc);

        // 3. 浏览按钮（可选，打开文件选择器）
        rightGbc.gridy++;
        JButton browseBtn = new JButton("浏览...");
        browseBtn.addActionListener(e -> {
            JFileChooser fileChooser = new JFileChooser();
            fileChooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
            fileChooser.setCurrentDirectory(new File(logPathField.getText()));
            int result = fileChooser.showOpenDialog(rightPanel);
            if (result == JFileChooser.APPROVE_OPTION) {
                logPathField.setText(fileChooser.getSelectedFile().getAbsolutePath());
            }
        });
        // 让按钮靠右显示
        JPanel browsePanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        browsePanel.add(browseBtn);
        rightPanel.add(browsePanel, rightGbc);
        // 4. 日志存储时间（单位：天）
        rightGbc.gridy++;
        JLabel logRetentionLabel = new JLabel("日志存储时间（天）:");
        rightPanel.add(logRetentionLabel, rightGbc);

        rightGbc.gridy++;
        JTextField logRetentionField = new JTextField(5);
        logRetentionField.setText(String.valueOf(DnslogConfig.getInstance().logRetentionDays));
        rightPanel.add(logRetentionField, rightGbc);

        // 4. 绑定启用状态与输入框可见性
        enableLogRadio.addActionListener(e -> {
            boolean enabled = enableLogRadio.isSelected();
            logPathLabel.setVisible(enabled);
            logPathField.setVisible(enabled);
            browseBtn.setVisible(enabled);
            browsePanel.setVisible(enabled);
            logRetentionLabel.setVisible(enabled);
            logRetentionField.setVisible(enabled);
        });
        disableLogRadio.addActionListener(e -> {
            boolean enabled = enableLogRadio.isSelected();
            logPathLabel.setVisible(enabled);
            logPathField.setVisible(enabled);
            browseBtn.setVisible(enabled);
            browsePanel.setVisible(enabled);
            logRetentionLabel.setVisible(enabled);
            logRetentionField.setVisible(enabled);
        });

        // 填充空白区域
        rightGbc.gridy++;
        rightGbc.weighty = 1.0;
        rightPanel.add(new JPanel(), rightGbc);


        // ==============================================
        // 底部：保存配置按钮（跨三栏居中）
        // ==============================================
        JButton saveBtn = new JButton("保存配置");
        saveBtn.addActionListener(e -> {
            // 1. 保存DNSlog配置（复用原逻辑）
            String selectedPlatform = (String) platformSelector.getSelectedItem();
            String collabDomain = collabDomainField.getText().trim();
            String ceyeKey = ceyeApiKeyField.getText().trim();
            String ceyeDomain = ceyeApiDomainField.getText().trim();
            String targetDomain = targetDomainField.getText().trim();

            // 2. 保存扫描选项
            boolean fastJsonEnabled = fastJsonCheck.isSelected();
            boolean log4jEnabled = log4jCheck.isSelected();
            boolean springEnabled = springCheck.isSelected();
            // 3. 保存日志设置
            boolean logEnabled = enableLogRadio.isSelected();
            String logPath = logEnabled ? logPathField.getText().trim() : "";

            // 验证配置
            StringBuilder errorMsg = new StringBuilder();
            if ("ceye".equals(selectedPlatform)) {
                if (ceyeKey.isEmpty()) errorMsg.append("CEYE APIKey不能为空\n");
                if (ceyeDomain.isEmpty()) errorMsg.append("CEYE APIDomain不能为空\n");
            }
            if (logEnabled && logPath.isEmpty()) {
                errorMsg.append("日志存储位置不能为空\n");
            }
            // 保存日志存储时间
            int retentionDays = 7; // 默认7天
            try {
                retentionDays = Integer.parseInt(logRetentionField.getText().trim());
                if (retentionDays <= 0) {
                    errorMsg.append("日志存储时间必须为正整数\n");
                }
            } catch (NumberFormatException ex) {
                errorMsg.append("日志存储时间必须为数字\n");
            }

            if (errorMsg.length() > 0) {
                JOptionPane.showMessageDialog(rightPanel, "配置不完整：\n" + errorMsg, "保存失败", JOptionPane.ERROR_MESSAGE);
                return;
            }

            // 保存到配置单例（需扩展DnslogConfig添加新字段）
            DnslogConfig config = DnslogConfig.getInstance();
            config.platform = selectedPlatform;
            config.collaboratorDomain = collabDomain;
            config.ceyeApiKey = ceyeKey;
            config.ceyeApiDomain = ceyeDomain;
            config.targetDomain = targetDomain;
            config.donlogType = "ceye".equals(selectedPlatform) ? Config.DnslogType.CEYE : Config.DnslogType.COLLABORATOR;
            // 新增字段：扫描选项
            config.fastJsonScanEnabled = fastJsonEnabled;
            config.log4jScanEnabled = log4jEnabled;
            config.springScanEnabled = springEnabled;
            // 新增字段：日志设置
            config.logEnabled = logEnabled;
            config.logPath = logPath;
            config.logRetentionDays = retentionDays;

            // 持久化保存
            try {
                config.save();
                JOptionPane.showMessageDialog(middlePanel, "配置保存成功！", "成功", JOptionPane.INFORMATION_MESSAGE);
                montoyaApi.logging().logToOutput("配置已保存");
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(middlePanel, "保存失败：" + ex.getMessage(), "错误", JOptionPane.ERROR_MESSAGE);
            }
        });


        // ==============================================
        // 组装三栏布局到主配置面板
        // ==============================================
        // 左侧面板：占1/3宽度
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.weightx = 1.0; // 宽度权重
        mainConfigPanel.add(leftPanel, gbc);

        // 中间面板：占1/3宽度
        gbc.gridx = 1;
        gbc.weightx = 1.0;
        mainConfigPanel.add(middlePanel, gbc);

        // 右侧面板：占1/3宽度
        gbc.gridx = 2;
        gbc.weightx = 1.0;
        mainConfigPanel.add(rightPanel, gbc);

        // 底部保存按钮：跨三栏
        gbc.gridx = 0;
        gbc.gridy = 1;
        gbc.gridwidth = 3;
        gbc.weightx = 0;
        gbc.anchor = GridBagConstraints.CENTER;
        gbc.fill = GridBagConstraints.NONE;
        mainConfigPanel.add(saveBtn, gbc);

        return mainConfigPanel;
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

