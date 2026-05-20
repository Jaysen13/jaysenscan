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
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import burp.api.montoya.repeater.Repeater;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.*;
import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

public class MySuiteTab {
    private final JPanel panel;
    private final JTable requestTable;
    private final DefaultTableModel tableModel;
    private int requestIndex = 1;

    private final HttpRequestEditor requestEditor;
    private final HttpResponseEditor responseEditor;

    private final JSplitPane resultSplitPane;   // 垂直分割：上表格，下请求/响应
    private final JSplitPane detailSplitPane;   // 水平分割：左请求，右响应

    private final List<HttpRequestResponse> requestResponses = new ArrayList<>();
    private final Set<String> addedVulnUrls = new java.util.HashSet<>();
    private final MontoyaApi montoyaApi;
    private DnslogConfig dnslogConfig;

    public MySuiteTab(MontoyaApi montoyaApi) {
        this.montoyaApi = montoyaApi;
        this.dnslogConfig = DnslogConfig.getInstance();

        panel = new JPanel(new BorderLayout());

        // ======== 扫描结果页面 ========
        JPanel resultPanel = new JPanel(new BorderLayout());

        // 顶部：清空按钮
        JPanel topResultPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton clearBtn = new JButton("清空所有数据");
        clearBtn.addActionListener(e -> clearAllData());
        topResultPanel.add(clearBtn);
        resultPanel.add(topResultPanel, BorderLayout.NORTH);

        // 漏洞列表（表格）
        String[] columnNames = {"序号", "漏洞名称", "请求域名", "请求方法", "URL", "响应码", "响应长度"};
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

        // 请求/响应编辑器（只读）
        requestEditor = montoyaApi.userInterface().createHttpRequestEditor();
        responseEditor = montoyaApi.userInterface().createHttpResponseEditor();

        // 下部详情区域：左右分屏
        detailSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        detailSplitPane.setLeftComponent(requestEditor.uiComponent());
        detailSplitPane.setRightComponent(responseEditor.uiComponent());

        // 垂直分割：上表格，下详情
        resultSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        resultSplitPane.setTopComponent(tableScrollPane);
        resultSplitPane.setBottomComponent(detailSplitPane);

        resultPanel.add(resultSplitPane, BorderLayout.CENTER);

        // 表格选择事件
        requestTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int selectedRow = requestTable.getSelectedRow();
                if (selectedRow != -1 && selectedRow < requestResponses.size()) {
                    HttpRequestResponse rr = requestResponses.get(selectedRow);
                    requestEditor.setRequest(rr.request());
                    responseEditor.setResponse(rr.response());
                }
            }
        });

        // 初始分割比例
        resultPanel.addComponentListener(new ComponentAdapter() {
            @Override
            public void componentShown(ComponentEvent e) {
                resultSplitPane.setDividerLocation(0.25); // 上面占 1/3
                detailSplitPane.setDividerLocation(0.5);  // 左右各半
                detailSplitPane.setResizeWeight(0.5); // 拖动时保持等比例

            }
        });

        // ======== 配置页面 ========
        JPanel configPanel = createConfigPanel();

        // ======== 选项卡容器 ========
        JTabbedPane tabbedPane = new JTabbedPane();
        tabbedPane.addTab("扫描结果", resultPanel);
        tabbedPane.addTab("配置", configPanel);
        panel.add(tabbedPane, BorderLayout.CENTER);
    }

    private JPanel createConfigPanel() {
        JPanel mainConfigPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.fill = GridBagConstraints.BOTH;
        gbc.weighty = 0.0;

        // ==============================================
        // 第1列：DNSlog配置
        // ==============================================
        JPanel dnsPanel = new JPanel(new GridBagLayout());
        dnsPanel.setBorder(BorderFactory.createTitledBorder("DNSLOG配置"));
        GridBagConstraints dnsGbc = new GridBagConstraints();
        dnsGbc.insets = new Insets(5, 5, 5, 5);
        dnsGbc.anchor = GridBagConstraints.WEST;
        dnsGbc.fill = GridBagConstraints.HORIZONTAL;
        dnsGbc.gridx = 0;
        dnsGbc.gridwidth = 1;
        dnsGbc.weightx = 1.0;

        dnsGbc.gridy = 0;
        dnsPanel.add(new JLabel("DNSlog平台:"), dnsGbc);
        dnsGbc.gridy++;
        JComboBox<String> platformSelector = new JComboBox<>(new String[]{"collaborator", "ceye"});
        platformSelector.setSelectedItem(dnslogConfig.platform);
        dnsPanel.add(platformSelector, dnsGbc);

        dnsGbc.gridy++;
        dnsPanel.add(new JLabel("Collaborator域名:"), dnsGbc);
        dnsGbc.gridy++;
        JPanel collabDomainPanel = new JPanel(new BorderLayout());
        JTextField collabDomainField = new JTextField(20);
        collabDomainField.setText(dnslogConfig.collaboratorDomain);
        collabDomainPanel.add(collabDomainField, BorderLayout.CENTER);
        JButton generateBtn = new JButton("自动生成");
        generateBtn.addActionListener(e -> {
            String collaboratorDomain = CheckDnslogResult.createCollaborator(montoyaApi);
            collabDomainField.setText(collaboratorDomain);
            dnslogConfig.collaboratorDomain = collaboratorDomain;
            dnslogConfig.save();
        });
        collabDomainPanel.add(generateBtn, BorderLayout.EAST);
        dnsPanel.add(collabDomainPanel, dnsGbc);

        if (dnslogConfig.domainToClientMap.get(dnslogConfig.collaboratorDomain) == null || dnslogConfig.collaboratorDomain.isEmpty()) {
            String autoGeneratedDomain = CheckDnslogResult.createCollaborator(montoyaApi);
            collabDomainField.setText(autoGeneratedDomain);
            dnslogConfig.collaboratorDomain = autoGeneratedDomain;
            dnslogConfig.save();
        }

        dnsGbc.gridy++;
        JLabel apiKeyLabel = new JLabel("CEYE APIKey:");
        dnsPanel.add(apiKeyLabel, dnsGbc);
        dnsGbc.gridy++;
        JTextField ceyeApiKeyField = new JTextField(20);
        ceyeApiKeyField.setText(dnslogConfig.ceyeApiKey);
        dnsPanel.add(ceyeApiKeyField, dnsGbc);

        dnsGbc.gridy++;
        JLabel apiDomainLabel = new JLabel("CEYE APIDomain:");
        dnsPanel.add(apiDomainLabel, dnsGbc);
        dnsGbc.gridy++;
        JTextField ceyeApiDomainField = new JTextField(20);
        ceyeApiDomainField.setText(dnslogConfig.ceyeApiDomain);
        dnsPanel.add(ceyeApiDomainField, dnsGbc);

        dnsGbc.gridy++;
        dnsPanel.add(new JLabel("目标域名:"), dnsGbc);
        dnsGbc.gridy++;
        JTextField targetDomainField = new JTextField(20);
        targetDomainField.setText(dnslogConfig.targetDomain);
        dnsPanel.add(targetDomainField, dnsGbc);

        dnsGbc.gridy++;
        dnsGbc.weighty = 0.0;
        dnsPanel.add(new JPanel(), dnsGbc);

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
        // 加解密配置区域
        // ==============================================
        JPanel cryptoPanel = new JPanel(new GridBagLayout());
        cryptoPanel.setBorder(BorderFactory.createTitledBorder("加解密配置"));
        GridBagConstraints cryptoGbc = new GridBagConstraints();
        cryptoGbc.insets = new Insets(5, 5, 5, 5);
        cryptoGbc.anchor = GridBagConstraints.WEST;
        cryptoGbc.fill = GridBagConstraints.HORIZONTAL;
        cryptoGbc.gridx = 0;
        cryptoGbc.gridwidth = 1;
        cryptoGbc.weightx = 1.0;

        cryptoGbc.gridy = 0;
        JCheckBox enableCryptoCheck = new JCheckBox("启用接口加解密");
        enableCryptoCheck.setSelected(dnslogConfig.cryptoEnabled);
        cryptoPanel.add(enableCryptoCheck, cryptoGbc);

        cryptoGbc.gridy++;
        cryptoPanel.add(new JLabel("接口链接:"), cryptoGbc);
        cryptoGbc.gridy++;
        JTextField cryptoApiUrlField = new JTextField(20);
        cryptoApiUrlField.setText(dnslogConfig.cryptoApiUrl);
        cryptoPanel.add(cryptoApiUrlField, cryptoGbc);

        // ==============================================
        // 第2列：扫描选项
        // ==============================================
        JPanel scanPanel = new JPanel(new GridBagLayout());
        scanPanel.setBorder(BorderFactory.createTitledBorder("扫描选项"));
        GridBagConstraints scanGbc = new GridBagConstraints();
        scanGbc.insets = new Insets(5, 5, 5, 5);
        scanGbc.anchor = GridBagConstraints.WEST;
        scanGbc.gridx = 0;
        scanGbc.gridy = 0;
        scanGbc.gridwidth = 1;

        JCheckBox fastJsonCheck = new JCheckBox("FastJson扫描");
        fastJsonCheck.setSelected(dnslogConfig.fastJsonScanEnabled);
        scanPanel.add(fastJsonCheck, scanGbc);

        scanGbc.gridy++;
        JCheckBox log4jCheck = new JCheckBox("Log4J扫描");
        log4jCheck.setSelected(dnslogConfig.log4jScanEnabled);
        scanPanel.add(log4jCheck, scanGbc);

        scanGbc.gridy++;
        JCheckBox springCheck = new JCheckBox("Spring扫描");
        springCheck.setSelected(dnslogConfig.springScanEnabled);
        scanPanel.add(springCheck, scanGbc);

        scanGbc.gridy++;
        JCheckBox shiroCheck = new JCheckBox("Shiro扫描");
        shiroCheck.setSelected(dnslogConfig.shiroScanEnabled);
        scanPanel.add(shiroCheck, scanGbc);

        scanGbc.gridy++;
        scanGbc.weighty = 0.5;
        scanPanel.add(new JPanel(), scanGbc);

        // ==============================================
        // 第3列：Spring目录扫描配置
        // ==============================================
        JPanel dirPanel = new JPanel(new GridBagLayout());
        dirPanel.setBorder(BorderFactory.createTitledBorder("Spring目录扫描配置"));
        GridBagConstraints dirGbc = new GridBagConstraints();
        dirGbc.insets = new Insets(5, 5, 5, 5);
        dirGbc.anchor = GridBagConstraints.WEST;
        dirGbc.fill = GridBagConstraints.HORIZONTAL;
        dirGbc.gridx = 0;
        dirGbc.gridwidth = 1;

        dirGbc.gridy = 0;
        dirPanel.add(new JLabel("过滤后缀名（,分割）:"), dirGbc);
        dirGbc.gridy++;
        JTextField extField = new JTextField(20);
        extField.setText(dnslogConfig.filterExtensions);
        dirPanel.add(extField, dirGbc);

        dirGbc.gridy++;
        dirPanel.add(new JLabel("过滤关键词（,分割）:"), dirGbc);
        dirGbc.gridy++;
        JTextField keywordField = new JTextField(20);
        keywordField.setText(dnslogConfig.filterKeywords);
        dirPanel.add(keywordField, dirGbc);

        dirGbc.gridy++;
        dirPanel.add(new JLabel("扫描目录关键词（,分割）:"), dirGbc);
        dirGbc.gridy++;
        JTextField springKeywordField = new JTextField(20);
        springKeywordField.setText(dnslogConfig.springScanKeywords);
        dirPanel.add(springKeywordField, dirGbc);

        dirGbc.gridy++;
        dirPanel.add(new JLabel("扫描文件路径（*.txt）:"), dirGbc);
        dirGbc.gridy++;
        JPanel filePathPanel = new JPanel(new BorderLayout());
        JTextField springFilePathField = new JTextField(15);
        springFilePathField.setText(dnslogConfig.springScanFilePath);
        filePathPanel.add(springFilePathField, BorderLayout.CENTER);
        JButton browseSpringFileBtn = new JButton("浏览...");
        browseSpringFileBtn.addActionListener(e -> {
            JFileChooser fileChooser = new JFileChooser();
            fileChooser.setFileFilter(new javax.swing.filechooser.FileFilter() {
                @Override
                public boolean accept(File f) {
                    return f.isDirectory() || f.getName().toLowerCase().endsWith(".txt");
                }
                @Override
                public String getDescription() {
                    return "TXT文件 (*.txt)";
                }
            });
            int result = fileChooser.showOpenDialog(dirPanel);
            if (result == JFileChooser.APPROVE_OPTION) {
                springFilePathField.setText(fileChooser.getSelectedFile().getAbsolutePath());
            }
        });
        filePathPanel.add(browseSpringFileBtn, BorderLayout.EAST);
        dirPanel.add(filePathPanel, dirGbc);

        dirGbc.gridy++;
        dirGbc.weighty = 1.0;
        dirPanel.add(new JPanel(), dirGbc);

        // ==============================================
        // 第4列：日志设置
        // ==============================================
        JPanel logPanel = new JPanel(new GridBagLayout());
        logPanel.setBorder(BorderFactory.createTitledBorder("日志设置"));
        GridBagConstraints logGbc = new GridBagConstraints();
        logGbc.insets = new Insets(5, 5, 5, 5);
        logGbc.anchor = GridBagConstraints.WEST;
        logGbc.fill = GridBagConstraints.HORIZONTAL;
        logGbc.gridx = 0;
        logGbc.gridwidth = 2;

        logGbc.gridy = 0;
        JRadioButton enableLogRadio = new JRadioButton("启用日志保存");
        JRadioButton disableLogRadio = new JRadioButton("禁用日志保存");
        ButtonGroup logGroup = new ButtonGroup();
        logGroup.add(enableLogRadio);
        logGroup.add(disableLogRadio);
        enableLogRadio.setSelected(DnslogConfig.getInstance().logEnabled);
        JPanel logRadioPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        logRadioPanel.add(enableLogRadio);
        logRadioPanel.add(disableLogRadio);
        logPanel.add(logRadioPanel, logGbc);

        logGbc.gridy++;
        JLabel logPathLabel = new JLabel("日志存储位置:");
        logPanel.add(logPathLabel, logGbc);
        logGbc.gridy++;
        JTextField logPathField = new JTextField(20);
        logPathField.setText(DnslogConfig.getInstance().logPath);
        logPanel.add(logPathField, logGbc);

        logGbc.gridy++;
        JButton browseBtn = new JButton("浏览...");
        browseBtn.addActionListener(e -> {
            JFileChooser fileChooser = new JFileChooser();
            fileChooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
            fileChooser.setCurrentDirectory(new File(logPathField.getText()));
            int result = fileChooser.showOpenDialog(logPanel);
            if (result == JFileChooser.APPROVE_OPTION) {
                logPathField.setText(fileChooser.getSelectedFile().getAbsolutePath());
            }
        });
        JPanel browsePanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        browsePanel.add(browseBtn);
        logPanel.add(browsePanel, logGbc);

        logGbc.gridy++;
        JLabel logRetentionLabel = new JLabel("日志存储时间（天）:");
        logPanel.add(logRetentionLabel, logGbc);
        logGbc.gridy++;
        JTextField logRetentionField = new JTextField(5);
        logRetentionField.setText(String.valueOf(DnslogConfig.getInstance().logRetentionDays));
        logPanel.add(logRetentionField, logGbc);

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

        boolean logEnabled = enableLogRadio.isSelected();
        logPathLabel.setVisible(logEnabled);
        logPathField.setVisible(logEnabled);
        browseBtn.setVisible(logEnabled);
        browsePanel.setVisible(logEnabled);
        logRetentionLabel.setVisible(logEnabled);
        logRetentionField.setVisible(logEnabled);

        logGbc.gridy++;
        logGbc.weighty = 1.0;
        logPanel.add(new JPanel(), logGbc);

        // ==============================================
        // 保存按钮
        // ==============================================
        JButton saveBtn = new JButton("保存配置");
        saveBtn.addActionListener(e -> {
            String selectedPlatform = (String) platformSelector.getSelectedItem();
            String collabDomain = collabDomainField.getText().trim();
            String ceyeKey = ceyeApiKeyField.getText().trim();
            String ceyeDomain = ceyeApiDomainField.getText().trim();
            String targetDomain = targetDomainField.getText().trim();

            boolean fastJsonEnabled = fastJsonCheck.isSelected();
            boolean log4jEnabled = log4jCheck.isSelected();
            boolean springEnabled = springCheck.isSelected();
            boolean shiroEnabled = shiroCheck.isSelected();

            boolean logEnabled2 = enableLogRadio.isSelected();
            String logPath = logEnabled2 ? logPathField.getText().trim() : "";

            String filterExts = extField.getText().trim();
            String filterKeywords = keywordField.getText().trim();
            String springKeywords = springKeywordField.getText().trim();
            String springFilePath = springFilePathField.getText().trim();

            boolean cryptoEnabled = enableCryptoCheck.isSelected();
            String cryptoApiUrl = cryptoApiUrlField.getText().trim();

            StringBuilder errorMsg = new StringBuilder();
            if ("ceye".equals(selectedPlatform)) {
                if (ceyeKey.isEmpty()) errorMsg.append("CEYE APIKey不能为空\n");
                if (ceyeDomain.isEmpty()) errorMsg.append("CEYE APIDomain不能为空\n");
            }
            if (cryptoEnabled && cryptoApiUrl.isEmpty()) errorMsg.append("启用接口加解密时，接口链接不能为空\n");
            if (cryptoEnabled && !cryptoApiUrl.startsWith("http://") && !cryptoApiUrl.startsWith("https://")) errorMsg.append("接口链接格式错误\n");
            if (logEnabled2 && logPath.isEmpty()) errorMsg.append("日志存储位置不能为空\n");

            int retentionDays = 7;
            try {
                retentionDays = Integer.parseInt(logRetentionField.getText().trim());
                if (retentionDays <= 0) errorMsg.append("日志存储时间必须为正整数\n");
            } catch (NumberFormatException ex) {
                errorMsg.append("日志存储时间必须为数字\n");
            }

            if (!filterExts.isEmpty()) {
                for (String ext : filterExts.split(",")) if (ext.trim().isEmpty()) errorMsg.append("过滤后缀名格式错误\n");
            }
            if (!filterKeywords.isEmpty()) {
                for (String kw : filterKeywords.split(",")) if (kw.trim().isEmpty()) errorMsg.append("过滤关键词格式错误\n");
            }
            if (springEnabled && !springFilePath.isEmpty()) {
                File f = new File(springFilePath);
                if (!f.exists() || !f.isFile() || !f.getName().toLowerCase().endsWith(".txt")) errorMsg.append("Spring扫描文件路径无效\n");
            }

            if (errorMsg.length() > 0) {
                JOptionPane.showMessageDialog(logPanel, "配置不完整：\n" + errorMsg, "保存失败", JOptionPane.ERROR_MESSAGE);
                return;
            }

            DnslogConfig config = DnslogConfig.getInstance();
            config.platform = selectedPlatform;
            config.collaboratorDomain = collabDomain;
            config.ceyeApiKey = ceyeKey;
            config.ceyeApiDomain = ceyeDomain;
            config.targetDomain = targetDomain;
            config.donlogType = "ceye".equals(selectedPlatform) ? Config.DnslogType.CEYE : Config.DnslogType.COLLABORATOR;
            config.fastJsonScanEnabled = fastJsonEnabled;
            config.log4jScanEnabled = log4jEnabled;
            config.springScanEnabled = springEnabled;
            config.shiroScanEnabled = shiroEnabled;
            config.logEnabled = logEnabled2;
            config.logPath = logPath;
            config.logRetentionDays = retentionDays;
            config.filterExtensions = filterExts;
            config.filterKeywords = filterKeywords;
            config.springScanKeywords = springKeywords;
            config.springScanFilePath = springFilePath;
            config.cryptoEnabled = cryptoEnabled;
            config.cryptoApiUrl = cryptoApiUrl;

            try {
                config.save();
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(scanPanel, "保存失败：" + ex.getMessage(), "错误", JOptionPane.ERROR_MESSAGE);
            }
        });

        // ==============================================
        // 组装四列布局
        // ==============================================
        gbc.gridx = 0; gbc.gridy = 0; gbc.weightx = 1.0;
        mainConfigPanel.add(dnsPanel, gbc);
        gbc.gridy++;
        mainConfigPanel.add(cryptoPanel, gbc);

        gbc.gridx = 1; gbc.gridy = 0; gbc.weightx = 1.0;
        mainConfigPanel.add(scanPanel, gbc);

        gbc.gridx = 2; gbc.gridy = 0; gbc.weightx = 1.0;
        mainConfigPanel.add(dirPanel, gbc);

        gbc.gridx = 3; gbc.gridy = 0; gbc.weightx = 1.0;
        mainConfigPanel.add(logPanel, gbc);

        gbc.gridx = 0; gbc.gridy = 1; gbc.gridwidth = 4; gbc.weightx = 0;
        gbc.anchor = GridBagConstraints.CENTER;
        gbc.fill = GridBagConstraints.NONE;
        mainConfigPanel.add(saveBtn, gbc);

        return mainConfigPanel;
    }

    // 其余方法（右键菜单、快捷键、发送Repeater、清空、添加记录）与原代码完全一致
    private void initTableRightMenu() {
        JPopupMenu rightMenu = new JPopupMenu();

        JMenuItem deleteItem = new JMenuItem("删除选中行");
        deleteItem.addActionListener(e -> {
            int selectedRow = requestTable.getSelectedRow();
            if (selectedRow != -1) {
                tableModel.removeRow(selectedRow);
                requestResponses.remove(selectedRow);
                if (tableModel.getRowCount() == 0) {
                    requestEditor.setRequest(HttpRequest.httpRequest("GET / HTTP/1.1\nHost: placeholder"));
                    responseEditor.setResponse(HttpResponse.httpResponse("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"));
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
        montoyaApi.repeater().sendToRepeater(rr.request());
    }

    private void clearAllData() {
        tableModel.setRowCount(0);
        requestResponses.clear();
        requestIndex = 1;
        addedVulnUrls.clear();
        requestEditor.setRequest(HttpRequest.httpRequest("GET / HTTP/1.1\nHost: placeholder"));
        responseEditor.setResponse(HttpResponse.httpResponse("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"));
    }

    public void addRequestInfo(HttpRequestResponse rr, String vulnerabilityName) {
        String url = rr.request().url();
        String dedupKey = vulnerabilityName + "|||" + url;
        if (!addedVulnUrls.add(dedupKey)) {
            return;
        }
        String domain = rr.request().headerValue("Host");
        String method = rr.request().method();
        String path = rr.request().path();
        int statusCode = rr.response().statusCode();
        int responseLength = rr.response().body().length();

        Object[] rowData = {requestIndex++, vulnerabilityName, domain, method, path, statusCode, responseLength};
        tableModel.addRow(rowData);
        requestResponses.add(rr);

        if (tableModel.getRowCount() == 1) {
            requestEditor.setRequest(rr.request());
            responseEditor.setResponse(rr.response());
        }
    }

    public Component getUiComponent() {
        return panel;
    }
}