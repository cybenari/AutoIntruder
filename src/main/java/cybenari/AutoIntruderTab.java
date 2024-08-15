package cybenari;

import static burp.api.montoya.ui.editor.EditorOptions.READ_ONLY;

import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.UnsupportedFlavorException;
import java.awt.event.ActionEvent;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.awt.event.ActionListener;
import java.awt.event.FocusEvent;
import java.awt.event.FocusListener;
import java.awt.event.KeyEvent;
import java.awt.event.KeyListener;
import java.awt.event.MouseAdapter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.Optional;
import java.util.Properties;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.table.TableRowSorter;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.UserInterface;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import cybenari.models.MyAbstractTableModel;
import cybenari.models.RequestsTableModel;
import cybenari.models.ResultsTableModel;
import cybenari.models.RulesTableModel;
import cybenari.rules.*;

import cybenari.rules.AbstractRule.OPERATION;
import cybenari.rules.AbstractRule.REQUEST_RESPONSE;

public class AutoIntruderTab extends JPanel {

	private RequestsTableModel requestsTableModel;
	private ResultsTableModel resultsTableModel;
	private RulesTableModel rulesTableModel;
	private RequestSendingManager sendingManager;
	JTable rulesTable;
	private MontoyaApi api;

	public AutoIntruderTab(MontoyaApi api) {

		this.api = api;
		requestsTableModel = new RequestsTableModel(api.logging());
		resultsTableModel = new ResultsTableModel(api.logging());
		rulesTableModel = new RulesTableModel();
		addDefaultRules();
		this.sendingManager = new RequestSendingManager(resultsTableModel, api);

		this.setLayout(new BorderLayout(0, 0));
		this.add(constructLoggerTab(requestsTableModel, api.logging(), resultsTableModel));

	}

	private void addDefaultRules() {
		InScopeRule rule = new InScopeRule();
		rule.setEnabled(true);
		rule.setMatchPattern(".");
		rule.setOperation(OPERATION.AND);
		rule.setRequestOrResponse(REQUEST_RESPONSE.REQUEST);

		this.rulesTableModel.add(rule);
	}

	private Component constructLoggerTab(RequestsTableModel requestsTableModel, Logging logging,
			ResultsTableModel resultsTableModel) {

		JPanel mainPanel = new JPanel();
		mainPanel.setLayout(new BorderLayout(0, 0));

		JTabbedPane tabbedPane = new JTabbedPane();

		// Adding tabs to the tabbed pane
		tabbedPane.addTab("Configuration", generateConfigurationPanel(logging, requestsTableModel));
		tabbedPane.addTab("Payloads", generatePayloadsPanel(requestsTableModel, resultsTableModel));
		tabbedPane.addTab("Requests", generateResultsPanel(resultsTableModel));

		// Adding the tabbed pane to the Main Panel
		mainPanel.add(tabbedPane);

		return mainPanel;
	}

	private JPanel generateResultsPanel(ResultsTableModel resultsTableModel) {

		JPanel newResultsPanel = new JPanel();
		newResultsPanel.setLayout(new BorderLayout(0, 0));

		// tabs with request/response viewers
		JTabbedPane requestsResponsesTabs = new JTabbedPane();

		UserInterface userInterface = api.userInterface();

		HttpRequestEditor originalRequestViewer = userInterface.createHttpRequestEditor(READ_ONLY);
		HttpRequestEditor modifiedRequestViewer = userInterface.createHttpRequestEditor();
		HttpResponseEditor originalResponseViewer = userInterface.createHttpResponseEditor(READ_ONLY);
		HttpResponseEditor modifiedResponseViewer = userInterface.createHttpResponseEditor(READ_ONLY);

		JTabbedPane original = new JTabbedPane();
		JTabbedPane modified = new JTabbedPane();
		requestsResponsesTabs.addTab("Original", original);
		requestsResponsesTabs.addTab("Modified", modified);

		JSplitPane requestResponseSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
		original.add(requestResponseSplitPane);

		JSplitPane modifiedRequestResponseSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
		modified.add(modifiedRequestResponseSplitPane);

		requestResponseSplitPane.add(originalRequestViewer.uiComponent());
		requestResponseSplitPane.add(originalResponseViewer.uiComponent());
		modifiedRequestResponseSplitPane.add(modifiedRequestViewer.uiComponent());
		modifiedRequestResponseSplitPane.add(modifiedResponseViewer.uiComponent());

		// table of log entries
		JTable table = new JTable(resultsTableModel) {
			@Override
			public void changeSelection(int rowIndex, int columnIndex, boolean toggle, boolean extend) {
				// show the log entry for the selected row

				HttpRequest modifiedRequest = modifiedRequestViewer.getRequest();

				// saveChangesToTableItem(this, resultsTableModel, modifiedRequest);

				int modelRow = convertRowIndexToModel(rowIndex);
				AttackCandidate candidate = resultsTableModel.get(modelRow);
				originalRequestViewer.setRequest(candidate.getOriginalRequest());
				modifiedRequestViewer.setRequest(candidate.getModifiedRequest());
				originalResponseViewer.setResponse(candidate.getOriginalResponse());
				modifiedResponseViewer.setResponse(candidate.getAttackResponse());

				super.changeSelection(rowIndex, columnIndex, toggle, extend);
			}

		};

		// ugly :( but here i'm adding a keyboard event listener and a mouse event
		// listener to all components under the modified requests tab
		addKeyListenerToAllComponents(modifiedRequestResponseSplitPane,
				getKeyListerner(table, resultsTableModel, modifiedRequestViewer),
				getMouseListener(table, resultsTableModel, modifiedRequestViewer));

		TableRowSorter<ResultsTableModel> sorter = new TableRowSorter<>(resultsTableModel);
		table.setRowSorter(sorter);

		JPopupMenu popupMenu = new JPopupMenu();
		JMenuItem disableMenuItemView = new JMenuItem("Disable");
		JMenuItem enableMenuItemView = new JMenuItem("Enable");
		JMenuItem deleteMenuItemView = new JMenuItem("Delete");
		popupMenu.add(disableMenuItemView);
		popupMenu.add(enableMenuItemView);
		popupMenu.add(deleteMenuItemView);

		// right click->delete item
		deleteMenuItemView.addActionListener(e -> {
			removeSelectedItems(table, resultsTableModel);

		});

		// right click->disable item
		disableMenuItemView.addActionListener(e -> {
			disableSelectedTableItems(table, resultsTableModel);
		});

		// right click->enable item
		enableMenuItemView.addActionListener(e -> {
			enableSelectedTableItems(table, resultsTableModel);
		});

		// Add a mouse listener to the table for the popup menu
		table.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseReleased(MouseEvent e) {
				if (e.getButton() == MouseEvent.BUTTON3) {
					// Check if right click

					int rowIndex = table.getSelectedRow();
					if (rowIndex < 0)
						return;

					popupMenu.show(e.getComponent(), e.getX(), e.getY());
				}
			}
		});

		JLabel numberOfThreadsLabel = new JLabel();
		numberOfThreadsLabel.setText("Number of Threads");
		JTextField numberOfThreads = new JTextField();
		numberOfThreads.setText(String.valueOf(sendingManager.getMaxNumberOfThreads()));

		JLabel requestDelayLabel = new JLabel();
		requestDelayLabel.setText("Request delay for each thread (ms)");
		JTextField requestDelayTextField = new JTextField();
		requestDelayTextField.setText(String.valueOf(sendingManager.getRequestDelay()));

		JButton startAttackButton = new JButton("Start Attack");
		JButton stoptAttackButton = new JButton("Stop Attack");
		JButton clearAllButton = new JButton("Clear All");

		clearAllButton.addActionListener(e -> {

			// this.sendingManager.stopAllThreads();
			this.resultsTableModel.removeAll();

		});

		startAttackButton.addActionListener(e -> {

			sendingManager.setRequestDelay(Long.parseLong(requestDelayTextField.getText()));
			sendingManager.setNumberOfThreads(Integer.parseInt(numberOfThreads.getText()));
			sendingManager.executeAll();

		});

		stoptAttackButton.addActionListener(e -> {
			this.sendingManager.stopAllThreads();

		});

		JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
		splitPane.setRightComponent(requestsResponsesTabs);

		JScrollPane scrollPane = new JScrollPane(table);
		splitPane.setLeftComponent(scrollPane);

		JPanel northPanel = new JPanel();
		northPanel.setLayout(new FlowLayout(FlowLayout.CENTER, 5, 5));
		northPanel.add(numberOfThreadsLabel);
		northPanel.add(numberOfThreads);
		northPanel.add(requestDelayLabel);
		northPanel.add(requestDelayTextField);
		northPanel.add(startAttackButton);
		northPanel.add(stoptAttackButton);
		northPanel.add(clearAllButton);

		newResultsPanel.add(northPanel, BorderLayout.NORTH);
		newResultsPanel.add(splitPane, BorderLayout.CENTER);

		return newResultsPanel;

	}

	private JPanel generateConfigurationPanel(Logging logging, RequestsTableModel tableModel) {

		JPanel configurationTab = new JPanel();

		// Second tab with a text field and a label

		configurationTab.setLayout(new BorderLayout());

		JPanel leftPanel = new JPanel();
		leftPanel.setLayout(new GridBagLayout());
		GridBagConstraints gbc = new GridBagConstraints();
		gbc.insets = new Insets(5, 5, 5, 5);
		gbc.fill = GridBagConstraints.NONE;
		gbc.anchor = GridBagConstraints.NORTHWEST;

		JPanel rightPanel = new JPanel();
		rightPanel.setLayout(new BorderLayout());

		// Create a JSplitPane with left and right panels
		JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, leftPanel, rightPanel);
		splitPane.setDividerLocation(0.3); // Set the initial divider location (30% of the width)
		splitPane.setResizeWeight(0.3); // Set the resize weight to distribute extra space (70% to the right panel)
		// splitPane.setEnabled(false);

		JTextField parameterPatternTextField = new JTextField();
		parameterPatternTextField.setColumns(20);
		parameterPatternTextField.setText(".*");

		// ComboBox setup
		JComboBox<String> optionsComboBox = new JComboBox<>();
		optionsComboBox.addItem(" ");

		// generate regex options
		Properties properties = PayloadScraper.getRegexOptions();
		Enumeration<?> propertyNames = properties.propertyNames();
		// Iterating over the keys
		while (propertyNames.hasMoreElements()) {

			optionsComboBox.addItem((String) propertyNames.nextElement());
		}

		// actions listener on options options box
		optionsComboBox.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				String selectedItem = (String) optionsComboBox.getSelectedItem();
				// Set the selected item as the text of the JTextField

				parameterPatternTextField.setText(properties.getProperty(selectedItem));

			}
		});

		JLabel paramLabel = new JLabel("Replace Pattern (Regex)");
		JLabel builtInRegexLabel = new JLabel("Built-in Regex");

		JPanel methodsPanel = new JPanel();

		JCheckBox getMethodCheckbox = new JCheckBox("GET");
		getMethodCheckbox.setSelected(true);
		methodsPanel.add(getMethodCheckbox);

		JCheckBox postMethodCheckbox = new JCheckBox("POST");
		postMethodCheckbox.setSelected(true);
		methodsPanel.add(postMethodCheckbox);

		JCheckBox putMethodCheckbox = new JCheckBox("PUT");
		methodsPanel.add(putMethodCheckbox);

		JCheckBox deleteMethodCheckbox = new JCheckBox("DELETE");
		methodsPanel.add(deleteMethodCheckbox);

		JCheckBox patchMethodCheckbox = new JCheckBox("PATCH");
		patchMethodCheckbox.setSelected(true);
		methodsPanel.add(patchMethodCheckbox);

		JCheckBox optionsMethodCheckbox = new JCheckBox("OPTIONS");
		methodsPanel.add(optionsMethodCheckbox);

		// param type panel
		JPanel paramTypePanel = new JPanel();
		JLabel paramTypeLabel = new JLabel("Only replace in these params types:");
		JCheckBox URLparamsCheckbox = new JCheckBox("Query Params");
		URLparamsCheckbox.setSelected(true);

		JCheckBox pathParamsCheckbox = new JCheckBox("Path Params");
		pathParamsCheckbox.setSelected(true);

		JCheckBox bodyParamsCheckbox = new JCheckBox("Body Params");
		bodyParamsCheckbox.setSelected(true);

		JCheckBox headerValuesParamsCheckbox = new JCheckBox("Header Values");
		bodyParamsCheckbox.setSelected(true);

		paramTypePanel.add(URLparamsCheckbox);
		paramTypePanel.add(pathParamsCheckbox);
		paramTypePanel.add(bodyParamsCheckbox);
		paramTypePanel.add(headerValuesParamsCheckbox);

		JButton findRequestsButton = new JButton("Find matching Requests");
		findRequestsButton.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {

				if (isValidRegex(parameterPatternTextField.getText())) {
					MatchRule rule = new MatchRule();
					rule.setGetMethodEnabled(getMethodCheckbox.isSelected());
					rule.setPostMethodEnabled(postMethodCheckbox.isSelected());
					rule.setPutMethodEnabled(putMethodCheckbox.isSelected());
					rule.setDeleteMethodEnabled(deleteMethodCheckbox.isSelected());
					rule.setPatchMethodEnabled(patchMethodCheckbox.isSelected());
					rule.setOptionsMethodEnabled(optionsMethodCheckbox.isSelected());
					rule.setURLParamEnabled(URLparamsCheckbox.isSelected());
					rule.setPathParamEnabled(pathParamsCheckbox.isSelected());
					rule.setBodyParamEnabled(bodyParamsCheckbox.isSelected());
					rule.setHeaderValuesEnabled(headerValuesParamsCheckbox.isSelected());

					try {
						rule.setParameterPattern(Pattern.compile(parameterPatternTextField.getText()));
					} catch (PatternSyntaxException exception) {
						logging.logToError(exception.getDescription());
					}

					logging.logToOutput(rule.toString());

					AnalysisEngine engine = new AnalysisEngine(logging);

					ArrayList<ProxyHttpRequestResponse> history = (ArrayList<ProxyHttpRequestResponse>) api.proxy()
							.history();

					for (ProxyHttpRequestResponse requestResponse : history) {

						ArrayList<AttackCandidate> attackCandidates = engine.analyzeRequest(requestResponse,
								rulesTableModel.getAll(), rule);
						for (AttackCandidate candidate : attackCandidates) {

							if (!tableModel.contains(candidate)) {
								tableModel.add(candidate);
							}

						}
					}

					if (tableModel.getRowCount() == 0) {
						JOptionPane.showMessageDialog(builtInRegexLabel, "No Results Found");
					}

				} else {
					JOptionPane.showMessageDialog(builtInRegexLabel,
							"Parameter pattern is not a valid Regular Expression", "Error", JOptionPane.ERROR_MESSAGE);
				}
			}
		});

		JPanel rulesPanel = generateRulesPanel();
		JLabel rulesLabel = new JLabel("Additional Filter Rules");

		JPanel rulesButtonsPanel = generateRuleButtonsPanel();

		rightPanel.add(generateRequestsTab(requestsTableModel), BorderLayout.CENTER);

		// panel for the labels and textbox of the paramter pattern
		JPanel parameterPanel = new JPanel(new GridBagLayout());
		GridBagConstraints Panelgbc = new GridBagConstraints();
		Panelgbc.insets = new Insets(5, 5, 5, 5);
		Panelgbc.fill = GridBagConstraints.NONE;
		Panelgbc.anchor = GridBagConstraints.NORTHWEST;

		Panelgbc.gridx = 0;
		Panelgbc.gridy = 0;
		parameterPanel.add(paramLabel, Panelgbc);

		Panelgbc.gridx = 1;
		parameterPanel.add(builtInRegexLabel, Panelgbc);

		Panelgbc.gridy = 1;
		Panelgbc.gridx = 0;
		parameterPanel.add(parameterPatternTextField, Panelgbc);

		Panelgbc.gridx = 1;
		parameterPanel.add(optionsComboBox, Panelgbc);

		// First row:
		gbc.gridx = 0;
		gbc.gridy = 0;
		leftPanel.add(parameterPanel, gbc);

		gbc.gridy = 3;
		leftPanel.add(paramTypeLabel, gbc);

		gbc.gridy = 4;
		leftPanel.add(paramTypePanel, gbc);

		gbc.gridy = 8;
		leftPanel.add(rulesLabel, gbc);

		gbc.gridy = 9;
		leftPanel.add(rulesPanel, gbc);

		gbc.gridy = 10;
		leftPanel.add(rulesButtonsPanel, gbc);

		gbc.gridy = 11;
		leftPanel.add(findRequestsButton, gbc);

		configurationTab.add(splitPane, BorderLayout.CENTER);

		return configurationTab;
	}

	public static boolean isValidRegex(String regex) {
		try {
			Pattern.compile(regex);
			return true;
		} catch (PatternSyntaxException e) {
			return false;
		}
	}

	private JPanel generateRuleButtonsPanel() {
		JPanel buttonsPanel = new JPanel(new FlowLayout());

		JButton addButton = new JButton("Add");

		JButton removeButton = new JButton("Remove");

		addButton.addActionListener(e -> {
			// JWindow popupWindow = new JWindow();
			addButton.setEnabled(false);
			JDialog popupWindow = new JDialog();

			popupWindow.add(generateRulesPopUpMenu(popupWindow, addButton));
			popupWindow.setSize(400, 250);
			popupWindow.setVisible(true);
			popupWindow.setTitle("Add new Rule");
			popupWindow.setLocationRelativeTo(addButton);

		});

		removeButton.addActionListener(e -> {
			int[] selectedIndecies = rulesTable.getSelectedRows();
			for (int i = 0; i < rulesTableModel.getRowCount(); i++) {
				rulesTableModel.removeAt(selectedIndecies[i]);

			}
		});

		buttonsPanel.add(addButton);

		buttonsPanel.add(removeButton);

		return buttonsPanel;
	}

	private JPanel generateRulesPopUpMenu(JDialog thisDialog, JButton callerButton) {
		callerButton.setEnabled(true);
		JPanel addRuleMenu = new JPanel(new GridBagLayout());

		GridBagConstraints constraints = new GridBagConstraints();
		constraints.insets = new Insets(10, 10, 10, 10);
		constraints.anchor = GridBagConstraints.WEST;

		// row 1
		constraints.gridx = 0;
		constraints.gridy = 0;
		addRuleMenu.add(new JLabel("Request/Response:"), constraints);

		constraints.gridx = 1;
		JComboBox<String> requestResponseComboBox = new JComboBox<>();
		requestResponseComboBox.addItem("Request");
		requestResponseComboBox.addItem("Response");
		addRuleMenu.add(requestResponseComboBox, constraints);

		// Row 2
		constraints.gridx = 0;
		constraints.gridy = 1;
		addRuleMenu.add(new JLabel("Operation:"), constraints);

		constraints.gridx = 1;
		JComboBox<String> operationBox = new JComboBox<>();
		operationBox.addItem("OR");
		operationBox.addItem("AND");
		addRuleMenu.add(operationBox, constraints);

		// row 3
		constraints.gridx = 0;
		constraints.gridy = 2;
		addRuleMenu.add(new JLabel("Type"), constraints);

		constraints.gridx = 1;
		JComboBox<String> TypeBox = new JComboBox<>();
		TypeBox.addItem("Path");
		TypeBox.addItem("Header Name");
		TypeBox.addItem("Header Value");
		TypeBox.addItem("Method");
		TypeBox.addItem("Body");
		TypeBox.addItem("In Scope");
		TypeBox.addItem("Cookie Value");
		TypeBox.addItem("Status Code");
		addRuleMenu.add(TypeBox, constraints);

		// row 4
		constraints.gridx = 0;
		constraints.gridy = 3;
		constraints.fill = GridBagConstraints.HORIZONTAL;
		constraints.weightx = 1.0;
		addRuleMenu.add(new JLabel("Matches"), constraints);

		constraints.gridx = 1;
		JTextField pattern = new JTextField(20);
		pattern.setText("\\.*");
		addRuleMenu.add(pattern, constraints);

		// row 5
		constraints.gridx = 0;
		constraints.gridy = 4;
		JButton okButton = new JButton("OK");
		addRuleMenu.add(okButton, constraints);

		okButton.addActionListener(e -> {

			AbstractRule rule;

			switch ((String) TypeBox.getSelectedItem()) {
			case "Path":
				rule = new PathRule();
				break;
			case "Method":
				rule = new MethodRule();
				break;
			case "Header Name":
				rule = new HeaderNameRule();
				break;
			case "Header Value":
				rule = new HeaderValueRule();
				break;
			case "Body":
				rule = new BodyRule();
				break;
			case "In Scope":
				rule = new InScopeRule();
				break;
			case "Cookie Value":
				rule = new CookieValueRule();
				break;
			case "Status Code":
				rule = new StatusCodeRule();
				break;
			default:
				rule = new PathRule();
			}

			if (operationBox.getSelectedItem().equals("AND")) {
				rule.setOperation(OPERATION.AND);
			} else {
				rule.setOperation(OPERATION.OR);
			}

			if (requestResponseComboBox.getSelectedItem().equals("Request")) {
				rule.setRequestOrResponse(REQUEST_RESPONSE.REQUEST);
			} else {
				rule.setRequestOrResponse(REQUEST_RESPONSE.RESPONSE);
			}

			rule.setMatchPattern(pattern.getText());

			this.rulesTableModel.add(rule);
			thisDialog.dispose();
		});

		return addRuleMenu;

	}

	private JPanel generateRulesPanel() {

		JPanel panel = new JPanel(new BorderLayout());

		this.rulesTable = new JTable(rulesTableModel);
		JScrollPane scrollPane = new JScrollPane(rulesTable);

		panel.add(scrollPane, BorderLayout.NORTH);

		return panel;
	}

	private JPanel generateRequestsTab(RequestsTableModel tableModel) {
		JPanel newRequestsTab = new JPanel();
		newRequestsTab.setLayout(new BorderLayout(0, 0));

		// tabs with request/response viewers
		JTabbedPane requestsResponsesTabs = new JTabbedPane();
		JSplitPane requestResponseSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
		JSplitPane modifiedRequestResponseSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);

		requestsResponsesTabs.addTab("Original", requestResponseSplitPane);
		requestsResponsesTabs.add("Modified", modifiedRequestResponseSplitPane);
		UserInterface userInterface = api.userInterface();

		HttpRequestEditor originalRequestViewer = userInterface.createHttpRequestEditor(READ_ONLY);
		HttpRequestEditor modifiedRequestViewer = userInterface.createHttpRequestEditor();
		HttpResponseEditor originalResponseViewer = userInterface.createHttpResponseEditor(READ_ONLY);

		requestResponseSplitPane.add(originalRequestViewer.uiComponent());
		modifiedRequestResponseSplitPane.add(modifiedRequestViewer.uiComponent());
		requestResponseSplitPane.add(originalResponseViewer.uiComponent());

		requestResponseSplitPane.setDividerLocation(0.5);

		// table of log entries
		JTable table = new JTable(tableModel) {
			@Override
			public void changeSelection(int rowIndex, int columnIndex, boolean toggle, boolean extend) {
				// show the log entry for the selected row

				int modelRow = convertRowIndexToModel(rowIndex);
				// auto save request each time selection is changed

				// updated view
				AttackCandidate candidate = tableModel.get(modelRow);
				originalRequestViewer.setRequest(candidate.getOriginalRequest());
				modifiedRequestViewer.setRequest(candidate.getModifiedRequest());
				originalResponseViewer.setResponse(candidate.getOriginalResponse());

				super.changeSelection(rowIndex, columnIndex, toggle, extend);
			}

		};

		// ugly :( but here i'm adding a keyboard event listener and a mouse event
		// listener to all components under the modified requests tab
		addKeyListenerToAllComponents(modifiedRequestResponseSplitPane,
				getKeyListerner(table, requestsTableModel, modifiedRequestViewer),
				getMouseListener(table, requestsTableModel, modifiedRequestViewer));

		TableRowSorter<RequestsTableModel> sorter = new TableRowSorter<>(tableModel);
		table.setRowSorter(sorter);

		JPopupMenu popupMenu = new JPopupMenu();
		JMenuItem disableMenuItemView = new JMenuItem("Disable");
		JMenuItem enableMenuItemView = new JMenuItem("Enable");
		JMenuItem deleteMenuItemView = new JMenuItem("Delete");

		popupMenu.add(disableMenuItemView);
		popupMenu.add(enableMenuItemView);
		popupMenu.add(deleteMenuItemView);

		// right click->delete item
		deleteMenuItemView.addActionListener(e -> {
			removeSelectedItems(table, requestsTableModel);

		});

		// right click->disable item
		disableMenuItemView.addActionListener(e -> {
			disableSelectedTableItems(table, requestsTableModel);
		});

		// right click->enable item
		enableMenuItemView.addActionListener(e -> {

			enableSelectedTableItems(table, requestsTableModel);
		});

		// Add a mouse listener to the table for the popup menu
		table.addMouseListener(new MouseAdapter() {

			@Override
			public void mouseReleased(MouseEvent e) {
				if (e.getButton() == MouseEvent.BUTTON3) {
					// Check if right click

					int rowIndex = table.getSelectedRow();
					if (rowIndex < 0)
						return;

					popupMenu.show(e.getComponent(), e.getX(), e.getY());
				}
			}
		});

		JButton disableButton = new JButton("Disable");
		JButton enableButton = new JButton("Enable");
		JButton clearAllRequestsButton = new JButton("Clear All");

		clearAllRequestsButton.addActionListener(e -> {

			this.requestsTableModel.removeAll();

		});

		disableButton.addActionListener(e -> {
			disableSelectedTableItems(table, requestsTableModel);

		});

		enableButton.addActionListener(e -> {
			enableSelectedTableItems(table, requestsTableModel);

		});

		JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
		splitPane.setRightComponent(requestsResponsesTabs);

		JScrollPane scrollPane = new JScrollPane(table);
		splitPane.setLeftComponent(scrollPane);

		JPanel northPanel = new JPanel();
		northPanel.setLayout(new FlowLayout(FlowLayout.CENTER, 5, 5));
		northPanel.add(enableButton);
		northPanel.add(disableButton);
		northPanel.add(clearAllRequestsButton);

		newRequestsTab.add(northPanel, BorderLayout.NORTH);
		newRequestsTab.add(splitPane, BorderLayout.CENTER);

		return newRequestsTab;
	}

	private KeyListener getKeyListerner(JTable table, MyAbstractTableModel model,
			HttpRequestEditor modifiedRequestViewer) {
		KeyListener keyListener = new KeyListener() {
			@Override
			public void keyTyped(KeyEvent e) {

			}

			@Override
			public void keyPressed(KeyEvent e) {
				saveChanges(e);
			}

			@Override
			public void keyReleased(KeyEvent e) {

			}

			private void saveChanges(KeyEvent e) {
				
				HttpRequest modifiedRequest = modifiedRequestViewer.getRequest();
				saveChangesToTableItem(table, model, modifiedRequest);

			}
		};
		return keyListener;
	}

	private MouseListener getMouseListener(JTable table, MyAbstractTableModel model,
			HttpRequestEditor modifiedRequestViewer) {
		MouseListener mouseListener = new MouseListener() {
			@Override
			public void mouseClicked(MouseEvent e) {
				// Not needed for mouse exit detection
			}

			@Override
			public void mousePressed(MouseEvent e) {
				// Not needed for mouse exit detection
			}

			@Override
			public void mouseReleased(MouseEvent e) {
				// Not needed for mouse exit detection
			}

			@Override
			public void mouseEntered(MouseEvent e) {
				// Not needed for mouse exit detection
			}

			@Override
			public void mouseExited(MouseEvent e) {
				saveChanges(e);
			}

			private void saveChanges(MouseEvent e) {
				
				HttpRequest modifiedRequest = modifiedRequestViewer.getRequest();
				saveChangesToTableItem(table, model, modifiedRequest);
			}
		};
		return mouseListener;
	}

	// this is needed in order to detect any key presses on the editor tab, so I can
	// save any changes to it
	// we are adding a listener to all child components recursively and saving after
	// each key press.
	private void addKeyListenerToAllComponents(Container container, KeyListener keyListener,
			MouseListener mouseListener) {
		for (Component component : container.getComponents()) {
			// Add the KeyListener to the component
			component.addKeyListener(keyListener);
			component.addMouseListener(mouseListener);

			// If the component is a container, recurse into it
			if (component instanceof Container) {
				addKeyListenerToAllComponents((Container) component, keyListener, mouseListener);
			}
		}
	}

	private boolean modificationIsValid(HttpRequest modifiedRequest) {
		int count = 0;
		String requestString = modifiedRequest.toString();
		for (int i = 0; i < requestString.length(); i++) {
			if (requestString.charAt(i) == '§') {
				count++;
			}

			if (count > 2) {
				return false; // Early exit if more than 2 '$' characters found
			}
		}

		return count == 2;

	}

	private void removeSelectedItems(JTable table, MyAbstractTableModel myModel) {

		int[] selectedIndecies = table.getSelectedRows();

		// reverse order
		for (int i = selectedIndecies.length; i > 0; i--) {
			int modelRow = table.convertRowIndexToModel(selectedIndecies[i - 1]);
			myModel.removeAt(modelRow);
			myModel.fireTableRowsDeleted(modelRow, modelRow);
		}
	}

	private void enableSelectedTableItems(JTable table, MyAbstractTableModel myModel) {

		int[] selectRowIndexes = table.getSelectedRows();

		for (int i = 0; i < selectRowIndexes.length; i++) {
			int modelRow = table.convertRowIndexToModel(selectRowIndexes[i]);
			AttackCandidate candidate = myModel.get(modelRow);
			candidate.setEnabled(true);
		}

	}

	private void saveChangesToTableItem(JTable table, MyAbstractTableModel myModel, HttpRequest modifiedRequest) {
		int selectRowIndex = table.getSelectedRow();

		if (selectRowIndex >= 0) {
			int modelIndex = table.convertRowIndexToModel(selectRowIndex);

			AttackCandidate candidate = myModel.get(modelIndex);

			candidate.setModifiedRequest(modifiedRequest);
		}

	}

	private void disableSelectedTableItems(JTable table, MyAbstractTableModel myModel) {
		int[] selectRowIndexes = table.getSelectedRows();

		for (int i = 0; i < selectRowIndexes.length; i++) {
			int modelIndex = table.convertRowIndexToModel(selectRowIndexes[i]);
			AttackCandidate candidate = myModel.get(modelIndex);
			candidate.setEnabled(false);
		}
	}

	private JPanel generatePayloadsPanel(RequestsTableModel requestsTableModel, ResultsTableModel resultsTableModel) {
		// payloads Panel

		JPanel payloadsPanel = new JPanel();
		payloadsPanel.setLayout(new BorderLayout());

		JPanel parameterPanel = new JPanel(new GridBagLayout());
		GridBagConstraints Panelgbc = new GridBagConstraints();
		Panelgbc.insets = new Insets(5, 5, 5, 5);
		Panelgbc.fill = GridBagConstraints.NONE;
		Panelgbc.anchor = GridBagConstraints.NORTHWEST;

		// JPanel topPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
		JLabel payloadRegexLabel = new JLabel("Payload Regex:");
		JTextField payloadRegexTextField = new JTextField(40);
		payloadRegexTextField.setToolTipText("A regex pattern for fetching payloads");

		JButton generatePayloadsButton = new JButton("Auto Generate Payloads");
		JCheckBox inScopeOnlyCheckbox = new JCheckBox("Search payloads in-scope only");
		inScopeOnlyCheckbox.setSelected(true);

		// ComboBox setup
		JComboBox<String> optionsComboBox = new JComboBox<>();
		optionsComboBox.addItem("");

		// generate regex options
		Properties properties = PayloadScraper.getRegexOptions();
		Enumeration<?> propertyNames = properties.propertyNames();
		// Iterating over the keys
		while (propertyNames.hasMoreElements()) {

			optionsComboBox.addItem((String) propertyNames.nextElement());
		}

		// actions listener on options options box
		optionsComboBox.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				String selectedItem = (String) optionsComboBox.getSelectedItem();
				// Set the selected item as the text of the JTextField

				payloadRegexTextField.setText(properties.getProperty(selectedItem));

			}
		});

		payloadRegexTextField.setText("[a-zA-Z0-9]{15}");

		Panelgbc.gridx = 0;
		Panelgbc.gridy = 0;
		parameterPanel.add(new JLabel("Payload"), Panelgbc);

		Panelgbc.gridx = 1;
		parameterPanel.add(new JLabel("Built-in Regex"), Panelgbc);

		Panelgbc.gridx = 0;
		Panelgbc.gridy = 1;
		parameterPanel.add(payloadRegexTextField, Panelgbc);

		Panelgbc.gridx = 1;
		parameterPanel.add(optionsComboBox, Panelgbc);

		Panelgbc.gridx = 0;
		Panelgbc.gridy = 2;
		parameterPanel.add(inScopeOnlyCheckbox, Panelgbc);

		Panelgbc.gridx = 0;
		Panelgbc.gridy = 3;
		parameterPanel.add(generatePayloadsButton, Panelgbc);

		// payloadsPanel.setLayout(new BorderLayout());

		// Model for the list
		DefaultListModel<String> payloadsList = new DefaultListModel<>();

		// Setup JList
		JList<String> list = new JList<>(payloadsList);
		list.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);

		// Setup buttons and text field
		JButton addButton = new JButton("Add");
		JButton removeButton = new JButton("Remove");
		JButton clearButton = new JButton("Clear");
		JButton pasteButton = new JButton("Paste");
		JButton generatetAttackButton = new JButton("Attach Payloads");

		JTextField addTextField = new JTextField(30); // text field with 10 columns

		pasteButton.addActionListener(e -> {
			Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
			try {
				// Get the clipboard content as a string
				String clipboardText = (String) clipboard.getData(DataFlavor.stringFlavor);

				// Split the clipboard text by new lines and add each line to the list model
				String[] lines = clipboardText.split("\\R");
				for (String line : lines) {
					payloadsList.addElement(line);
				}
			} catch (UnsupportedFlavorException | IOException ex) {
				JOptionPane.showMessageDialog(payloadsPanel, "Failed to get clipboard content", "Error",
						JOptionPane.ERROR_MESSAGE);
			}

		});

		generatePayloadsButton.addActionListener(e -> {
			PayloadScraper scraper = new PayloadScraper();
			Pattern pattern = Pattern.compile(payloadRegexTextField.getText());

			scraper.setPayloadPattern(pattern);
			ArrayList<ProxyHttpRequestResponse> history = (ArrayList<ProxyHttpRequestResponse>) api.proxy().history();
			scraper.setHistory(history);
			scraper.setInScopeOnly(inScopeOnlyCheckbox.isSelected());

			payloadsList.addAll(scraper.findAllUniquePayloads());

		});

		generatetAttackButton.addActionListener(e -> {
			ArrayList<AttackCandidate> invalidCandidates = new ArrayList();

			if (validPayloadsAndCandidateSizes(requestsTableModel.getAllEnabled(), payloadsList, payloadsPanel)) {
				for (AttackCandidate candidate : requestsTableModel.getAllEnabled()) {
					for (int i = 0; i < payloadsList.size(); i++) {
						if (modificationIsValid(candidate.getModifiedRequest())) {
							resultsTableModel.add(candidate.cloneWithPayload(payloadsList.get(i)));
						} else {
							invalidCandidates.add(candidate);
						}

					}

				}
				if (invalidCandidates.size() > 0) {
					JOptionPane.showMessageDialog(payloadsPanel, invalidCandidates.size()
							+ " request/s have an invalid number of § placeholders. Only 2 are allowed per request.");
				}

				JOptionPane.showMessageDialog(payloadsPanel, "Requests Generated!");
			}

		});

		// need to remove in reverse order (from large to small)
		removeButton.addActionListener(e -> {
			int[] selectedIndecies = list.getSelectedIndices();

			for (int i = selectedIndecies.length; i > 0; i--) {
				payloadsList.remove(selectedIndecies[i - 1]);
			}

		});

		clearButton.addActionListener(e -> {
			payloadsList.clear(); // Clears the entire list
		});

		// Adding action listeners to buttons
		addButton.addActionListener(e -> {
			if (!addTextField.getText().isEmpty()) {
				payloadsList.addElement(addTextField.getText());
				addTextField.setText(""); // Clear the text field after adding the item
			}
		});

		// Panel for the list and button controls
		JPanel listPanel = new JPanel(new BorderLayout());
		listPanel.add(new JScrollPane(list), BorderLayout.CENTER);

		// Panel for the buttons on the left
		JPanel buttonPanel = new JPanel();
		buttonPanel.setLayout(new BoxLayout(buttonPanel, BoxLayout.Y_AXIS));
		buttonPanel.add(removeButton);
		buttonPanel.add(clearButton);
		buttonPanel.add(pasteButton);
		listPanel.add(buttonPanel, BorderLayout.WEST);

		// Panel for the add button and text field
		JPanel controlPanel = new JPanel();
		FlowLayout flowLayout = (FlowLayout) controlPanel.getLayout();
		flowLayout.setAlignment(FlowLayout.LEFT);

		controlPanel.add(addButton);
		controlPanel.add(addTextField);

		// Adding panels to the frame
		// topPanel.setPreferredSize(new Dimension(800, 180));
		payloadsPanel.add(parameterPanel, BorderLayout.NORTH);

		JPanel middlePanel = new JPanel();
		middlePanel.setLayout(new BorderLayout());

		middlePanel.setPreferredSize(new Dimension(800, 300));
		middlePanel.add(listPanel, BorderLayout.CENTER);
		middlePanel.add(controlPanel, BorderLayout.SOUTH);

		payloadsPanel.add(middlePanel, BorderLayout.CENTER);

		JPanel buttomPanel = new JPanel();
		buttomPanel.setPreferredSize(new Dimension(800, 120));
		buttomPanel.add(generatetAttackButton);
		payloadsPanel.add(buttomPanel, BorderLayout.SOUTH);

		return payloadsPanel;
	}

	private boolean validPayloadsAndCandidateSizes(ArrayList<AttackCandidate> enabledCandidates,
			DefaultListModel<String> payloads, Component c) {
		if (payloads.size() == 0) {
			JOptionPane.showMessageDialog(c, "Payload count cannot be 0.");
			return false;
		}
		if (enabledCandidates.size() == 0) {
			JOptionPane.showMessageDialog(c, "Requests count cannot be 0.");
			return false;
		}
		return true;

	}
}
