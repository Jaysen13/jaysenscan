import burp.api.montoya.MontoyaApi;
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
    private final JPanel configPanel;
    private boolean configExpanded = false;

    public MySuiteTab(MontoyaApi montoyaApi) {
        this.montoyaApi = montoyaApi;
        panel = new JPanel();
        panel.setLayout(new BorderLayout());
        this.dnslogConfig = DnslogConfig.getInstance();

        // 顶部区域：配置按钮 + 清空按钮
        JPanel topContainer = new JPanel(new BorderLayout());
        JPanel configButtonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton configBtn = new JButton("配置");
        configBtn.addActionListener(e -> toggleConfigPanel());
        configButtonPanel.add(configBtn);
        topContainer.add(configButtonPanel, BorderLayout.WEST);

        JPanel topRightPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton clearBtn = new JButton("清空所有数据");
        clearBtn.addActionListener(e -> clearAllData());
        topRightPanel.add(clearBtn);
        topContainer.add(topRightPanel, BorderLayout.EAST);

        // 配置面板
        configPanel = createConfigPanel();
        configPanel.setVisible(false);

        JPanel northPanel = new JPanel(new BorderLayout());
        northPanel.add(topContainer, BorderLayout.NORTH);
        northPanel.add(configPanel, BorderLayout.CENTER);
        panel.add(northPanel, BorderLayout.NORTH);

        // 中间区域：表格和请求响应展示
        mainSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);

        // 左半边表格（新增“漏洞名称”列）
        String[] columnNames = {"序号", "漏洞名称", "请求域名", "请求方法", "URL", "响应码"};
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

        // 表格点击事件
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

        // 分割面板比例设置
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
        JPanel mainConfigPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.fill = GridBagConstraints.BOTH;
        gbc.weighty = 1.0;


        // ==============================================
        // 第1列：DNSlog配置
        // ==============================================
        JPanel dnsPanel = new JPanel(new GridBagLayout());
        dnsPanel.setBorder(BorderFactory.createTitledBorder("DNSlog配置"));
        GridBagConstraints dnsGbc = new GridBagConstraints();
        dnsGbc.insets = new Insets(5, 5, 5, 5);
        dnsGbc.anchor = GridBagConstraints.WEST;
        dnsGbc.fill = GridBagConstraints.HORIZONTAL;
        dnsGbc.gridx = 0;
        dnsGbc.gridwidth = 2;

        // 1. DNSlog平台选择
        dnsGbc.gridy = 0;
        dnsPanel.add(new JLabel("DNSlog平台:"), dnsGbc);
        dnsGbc.gridy++;
        JComboBox<String> platformSelector = new JComboBox<>(new String[]{"collaborator", "ceye"});
        platformSelector.setSelectedItem(dnslogConfig.platform);
        dnsPanel.add(platformSelector, dnsGbc);

        // 2. Collaborator域名 + 自动生成按钮
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

        // 自动生成域名逻辑
        if (dnslogConfig.domainToClientMap.get(dnslogConfig.collaboratorDomain) == null || dnslogConfig.collaboratorDomain.isEmpty()) {
            String autoGeneratedDomain = CheckDnslogResult.createCollaborator(montoyaApi);
            collabDomainField.setText(autoGeneratedDomain);
            dnslogConfig.collaboratorDomain = autoGeneratedDomain;
            dnslogConfig.save();
            montoyaApi.logging().logToOutput("检测到未正确配置Collaborator域名，已自动生成");
        }

        // 3. CEYE APIKey
        dnsGbc.gridy++;
        JLabel apiKeyLabel = new JLabel("CEYE APIKey:");
        dnsPanel.add(apiKeyLabel, dnsGbc);
        dnsGbc.gridy++;
        JTextField ceyeApiKeyField = new JTextField(20);
        ceyeApiKeyField.setText(dnslogConfig.ceyeApiKey);
        dnsPanel.add(ceyeApiKeyField, dnsGbc);

        // 4. CEYE APIDomain
        dnsGbc.gridy++;
        JLabel apiDomainLabel = new JLabel("CEYE APIDomain:");
        dnsPanel.add(apiDomainLabel, dnsGbc);
        dnsGbc.gridy++;
        JTextField ceyeApiDomainField = new JTextField(20);
        ceyeApiDomainField.setText(dnslogConfig.ceyeApiDomain);
        dnsPanel.add(ceyeApiDomainField, dnsGbc);

        // 5. 目标域名
        dnsGbc.gridy++;
        dnsPanel.add(new JLabel("目标域名:"), dnsGbc);
        dnsGbc.gridy++;
        JTextField targetDomainField = new JTextField(20);
        targetDomainField.setText(dnslogConfig.targetDomain);
        dnsPanel.add(targetDomainField, dnsGbc);

        // 平台切换显隐控制
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
        scanGbc.weighty = 1.0;
        scanPanel.add(new JPanel(), scanGbc);


        // ==============================================
        // 第3列：目录配置 + Spring扫描配置
        // ==============================================
        JPanel dirPanel = new JPanel(new GridBagLayout());
        dirPanel.setBorder(BorderFactory.createTitledBorder("目录配置"));
        GridBagConstraints dirGbc = new GridBagConstraints();
        dirGbc.insets = new Insets(5, 5, 5, 5);
        dirGbc.anchor = GridBagConstraints.WEST;
        dirGbc.fill = GridBagConstraints.HORIZONTAL;
        dirGbc.gridx = 0;
        dirGbc.gridwidth = 1;

        // 1. 过滤后缀名输入框
        dirGbc.gridy = 0;
        dirPanel.add(new JLabel("过滤后缀名（,分割）:"), dirGbc);
        dirGbc.gridy++;
        JTextField extField = new JTextField(20);
        extField.setText(dnslogConfig.filterExtensions);
        dirPanel.add(extField, dirGbc);

        // 2. 过滤关键词输入框
        dirGbc.gridy++;
        dirPanel.add(new JLabel("过滤关键词（,分割）:"), dirGbc);
        dirGbc.gridy++;
        JTextField keywordField = new JTextField(20);
        keywordField.setText(dnslogConfig.filterKeywords);
        dirPanel.add(keywordField, dirGbc);

        // 3. 新增：Spring扫描配置区域（仅勾选Spring扫描时显示）
        dirGbc.gridy++;
        JPanel springScanPanel = new JPanel(new GridBagLayout());
        springScanPanel.setBorder(BorderFactory.createTitledBorder("Spring扫描配置"));
        GridBagConstraints springGbc = new GridBagConstraints();
        springGbc.insets = new Insets(5, 5, 5, 5);
        springGbc.anchor = GridBagConstraints.WEST;
        springGbc.fill = GridBagConstraints.HORIZONTAL;
        springGbc.gridx = 0;
        springGbc.gridwidth = 1;

        // 3.1 Spring扫描目录关键词输入框
        springGbc.gridy = 0;
        springScanPanel.add(new JLabel("扫描目录关键词（,分割）:"), springGbc);
        springGbc.gridy++;
        JTextField springKeywordField = new JTextField(20);
        springKeywordField.setText(dnslogConfig.springScanKeywords);
        springScanPanel.add(springKeywordField, springGbc);

        // 3.2 Spring扫描文件路径（指定txt文件）
        springGbc.gridy++;
        springScanPanel.add(new JLabel("扫描文件路径（*.txt）:"), springGbc);
        springGbc.gridy++;
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
            int result = fileChooser.showOpenDialog(springScanPanel);
            if (result == JFileChooser.APPROVE_OPTION) {
                springFilePathField.setText(fileChooser.getSelectedFile().getAbsolutePath());
            }
        });
        filePathPanel.add(browseSpringFileBtn, BorderLayout.EAST);
        springScanPanel.add(filePathPanel, springGbc);

        // 填充空白区域
        springGbc.gridy++;
        springGbc.weighty = 1.0;
        springScanPanel.add(new JPanel(), springGbc);

        // 绑定Spring扫描勾选框的显隐逻辑
        springScanPanel.setVisible(springCheck.isSelected());
        springCheck.addActionListener(e -> {
            springScanPanel.setVisible(springCheck.isSelected());
            dirPanel.revalidate();
            dirPanel.repaint();
        });

        // 将Spring扫描配置添加到目录配置下方
        dirPanel.add(springScanPanel, dirGbc);

        // 填充目录配置面板空白区域
        dirGbc.gridy++;
        dirGbc.weighty = 1.0;
        dirPanel.add(new JPanel(), dirGbc);


        // ==============================================
        // 第4列：日志设置（右上角）
        // ==============================================
        JPanel logPanel = new JPanel(new GridBagLayout());
        logPanel.setBorder(BorderFactory.createTitledBorder("日志设置"));
        GridBagConstraints logGbc = new GridBagConstraints();
        logGbc.insets = new Insets(5, 5, 5, 5);
        logGbc.anchor = GridBagConstraints.WEST;
        logGbc.fill = GridBagConstraints.HORIZONTAL;
        logGbc.gridx = 0;
        logGbc.gridwidth = 2;

        // 1. 日志启用单选框
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

        // 2. 日志存储位置
        logGbc.gridy++;
        JLabel logPathLabel = new JLabel("日志存储位置:");
        logPanel.add(logPathLabel, logGbc);

        logGbc.gridy++;
        JTextField logPathField = new JTextField(20);
        logPathField.setText(DnslogConfig.getInstance().logPath);
        logPanel.add(logPathField, logGbc);

        // 3. 浏览按钮
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

        // 4. 日志存储时间
        logGbc.gridy++;
        JLabel logRetentionLabel = new JLabel("日志存储时间（天）:");
        logPanel.add(logRetentionLabel, logGbc);

        logGbc.gridy++;
        JTextField logRetentionField = new JTextField(5);
        logRetentionField.setText(String.valueOf(DnslogConfig.getInstance().logRetentionDays));
        logPanel.add(logRetentionField, logGbc);

        // 绑定启用状态与可见性
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

        logGbc.gridy++;
        logGbc.weighty = 1.0;
        logPanel.add(new JPanel(), logGbc);


        // ==============================================
        // 保存按钮
        // ==============================================
        JButton saveBtn = new JButton("保存配置");
        saveBtn.addActionListener(e -> {
            // 保存DNSlog配置
            String selectedPlatform = (String) platformSelector.getSelectedItem();
            String collabDomain = collabDomainField.getText().trim();
            String ceyeKey = ceyeApiKeyField.getText().trim();
            String ceyeDomain = ceyeApiDomainField.getText().trim();
            String targetDomain = targetDomainField.getText().trim();

            // 保存扫描选项
            boolean fastJsonEnabled = fastJsonCheck.isSelected();
            boolean log4jEnabled = log4jCheck.isSelected();
            boolean springEnabled = springCheck.isSelected();

            // 保存日志设置
            boolean logEnabled = enableLogRadio.isSelected();
            String logPath = logEnabled ? logPathField.getText().trim() : "";

            // 保存目录配置
            String filterExts = extField.getText().trim();
            String filterKeywords = keywordField.getText().trim();

            // 保存Spring扫描配置
            String springKeywords = springKeywordField.getText().trim();
            String springFilePath = springFilePathField.getText().trim();

            // 验证配置
            StringBuilder errorMsg = new StringBuilder();
            if ("ceye".equals(selectedPlatform)) {
                if (ceyeKey.isEmpty()) errorMsg.append("CEYE APIKey不能为空\n");
                if (ceyeDomain.isEmpty()) errorMsg.append("CEYE APIDomain不能为空\n");
            }
            if (logEnabled && logPath.isEmpty()) {
                errorMsg.append("日志存储位置不能为空\n");
            }

            // 验证日志存储时间
            int retentionDays = 7;
            try {
                retentionDays = Integer.parseInt(logRetentionField.getText().trim());
                if (retentionDays <= 0) {
                    errorMsg.append("日志存储时间必须为正整数\n");
                }
            } catch (NumberFormatException ex) {
                errorMsg.append("日志存储时间必须为数字\n");
            }

            // 验证过滤后缀名
            if (!filterExts.isEmpty()) {
                String[] exts = filterExts.split(",");
                for (String ext : exts) {
                    if (ext.trim().isEmpty()) {
                        errorMsg.append("过滤后缀名格式错误：包含空项\n");
                        break;
                    }
                }
            }

            // 验证过滤关键词
            if (!filterKeywords.isEmpty()) {
                String[] keywords = filterKeywords.split(",");
                for (String kw : keywords) {
                    if (kw.trim().isEmpty()) {
                        errorMsg.append("过滤关键词格式错误：包含空项\n");
                        break;
                    }
                }
            }

            // 验证Spring扫描配置（仅当勾选时验证）
            if (springEnabled) {
                // 验证关键词格式
                if (!springKeywords.isEmpty()) {
                    String[] springKws = springKeywords.split(",");
                    for (String kw : springKws) {
                        if (kw.trim().isEmpty()) {
                            errorMsg.append("Spring扫描关键词格式错误：包含空项\n");
                            break;
                        }
                    }
                }
                // 验证文件路径（如果填写）
                if (!springFilePath.isEmpty()) {
                    File springFile = new File(springFilePath);
                    if (!springFile.exists() || !springFile.isFile() || !springFile.getName().toLowerCase().endsWith(".txt")) {
                        errorMsg.append("Spring扫描文件路径必须是存在的TXT文件\n");
                    }
                }
            }

            if (errorMsg.length() > 0) {
                JOptionPane.showMessageDialog(logPanel, "配置不完整：\n" + errorMsg, "保存失败", JOptionPane.ERROR_MESSAGE);
                return;
            }

            // 保存到配置
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
            config.logEnabled = logEnabled;
            config.logPath = logPath;
            config.logRetentionDays = retentionDays;
            config.filterExtensions = filterExts;
            config.filterKeywords = filterKeywords;
            config.springScanKeywords = springKeywords;
            config.springScanFilePath = springFilePath;

            // 持久化
            try {
                config.save();
                JOptionPane.showMessageDialog(scanPanel, "配置保存成功！", "成功", JOptionPane.INFORMATION_MESSAGE);
                montoyaApi.logging().logToOutput("配置已保存");
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(scanPanel, "保存失败：" + ex.getMessage(), "错误", JOptionPane.ERROR_MESSAGE);
            }
        });


        // ==============================================
        // 组装四列布局
        // ==============================================
        // 第1列：DNSlog配置
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.weightx = 1.0;
        mainConfigPanel.add(dnsPanel, gbc);

        // 第2列：扫描选项
        gbc.gridx = 1;
        gbc.weightx = 1.0;
        mainConfigPanel.add(scanPanel, gbc);

        // 第3列：目录配置
        gbc.gridx = 2;
        gbc.weightx = 1.0;
        mainConfigPanel.add(dirPanel, gbc);

        // 第4列：日志设置（右上角）
        gbc.gridx = 3;
        gbc.weightx = 1.0;
        mainConfigPanel.add(logPanel, gbc);

        // 保存按钮（跨四列）
        gbc.gridx = 0;
        gbc.gridy = 1;
        gbc.gridwidth = 4;
        gbc.weightx = 0;
        gbc.anchor = GridBagConstraints.CENTER;
        gbc.fill = GridBagConstraints.NONE;
        mainConfigPanel.add(saveBtn, gbc);

        return mainConfigPanel;
    }

    private void toggleConfigPanel() {
        configExpanded = !configExpanded;
        configPanel.setVisible(configExpanded);
        panel.revalidate();
        panel.repaint();
    }

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

    // 新增：带漏洞名称的添加方法
    public void addRequestInfo(HttpRequestResponse rr, String vulnerabilityName) {
        String domain = rr.request().headerValue("Host");
        String method = rr.request().method();
        String path = rr.request().path();
        int statusCode = rr.response().statusCode();
        String request = rr.request().toString();
        String response = rr.response().toString();
        Object[] rowData = {requestIndex++, vulnerabilityName, domain, method, path, statusCode};
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