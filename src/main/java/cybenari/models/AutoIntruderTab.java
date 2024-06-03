package cybenari.models;

import static burp.api.montoya.ui.editor.EditorOptions.READ_ONLY;

import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.UnsupportedFlavorException;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.Properties;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import javax.swing.*;
import javax.swing.table.TableRowSorter;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.ui.UserInterface;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import cybenari.AnalysisEngine;
import cybenari.AttackCandidate;
import cybenari.MatchRule;
import cybenari.PayloadScraper;
import cybenari.RequestSendingManager;
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
		this.sendingManager = new RequestSendingManager(resultsTableModel, api);

		this.setLayout(new BorderLayout(0, 0));
		this.add(constructLoggerTab(requestsTableModel, api.logging(), resultsTableModel));

	}

	private Component constructLoggerTab(RequestsTableModel requestsTableModel, Logging logging,
			ResultsTableModel resultsTableModel) {

		JPanel mainPanel = new JPanel();
		mainPanel.setLayout(new BorderLayout(0, 0));

		JTabbedPane tabbedPane = new JTabbedPane();

		// Adding tabs to the tabbed pane
		tabbedPane.addTab("Configuration", generateConfigurationPanel(logging, requestsTableModel));
		tabbedPane.addTab("Payloads", generatePayloadsPanel(requestsTableModel, resultsTableModel));
		tabbedPane.addTab("Results", generateResultsPanel(resultsTableModel));
		

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
		HttpRequestEditor modifiedRequestViewer = userInterface.createHttpRequestEditor(READ_ONLY);
		HttpResponseEditor originalResponseViewer = userInterface.createHttpResponseEditor(READ_ONLY);
		HttpResponseEditor modifiedResponseViewer = userInterface.createHttpResponseEditor(READ_ONLY);

		requestsResponsesTabs.addTab("Original Request", originalRequestViewer.uiComponent());
		requestsResponsesTabs.addTab("Original Response", originalResponseViewer.uiComponent());
		requestsResponsesTabs.addTab("Modified Request", modifiedRequestViewer.uiComponent());
		requestsResponsesTabs.addTab("Modified Response", modifiedResponseViewer.uiComponent());

		// table of log entries
		JTable table = new JTable(resultsTableModel) {
			@Override
			public void changeSelection(int rowIndex, int columnIndex, boolean toggle, boolean extend) {
				// show the log entry for the selected row

				int modelRow = convertRowIndexToModel(rowIndex);
				AttackCandidate candidate = resultsTableModel.get(modelRow);
				originalRequestViewer.setRequest(candidate.getOriginalRequest());
				modifiedRequestViewer.setRequest(candidate.getModifiedRequest());
				originalResponseViewer.setResponse(candidate.getOriginalResponse());
				modifiedResponseViewer.setResponse(candidate.getAttackResponse());

				super.changeSelection(rowIndex, columnIndex, toggle, extend);
			}

		};

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
		//splitPane.setEnabled(false);
		

		

		JTextField parameterPatternTextField = new JTextField();
		parameterPatternTextField.setColumns(20);

		// ComboBox setup
		JComboBox<String> optionsComboBox = new JComboBox<>();

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
		JLabel paramLabel = new JLabel("Parameter Pattern (Regex)");
		JLabel builtInRegexLabel = new JLabel("Built-in Regex:");

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
		
		
		//param type panel
		JPanel paramTypePanel = new JPanel();
		JLabel paramTypeLabel = new JLabel("Only replace in these params:");
		JCheckBox URLparamsCheckbox = new JCheckBox("Query Params");
		URLparamsCheckbox.setSelected(true);

		JCheckBox pathParamsCheckbox = new JCheckBox("Path Params");
		pathParamsCheckbox.setSelected(true);

		JCheckBox bodyParamsCheckbox = new JCheckBox("Body Params");
		bodyParamsCheckbox.setSelected(true);
		paramTypePanel.add(URLparamsCheckbox);
		paramTypePanel.add(pathParamsCheckbox);
		paramTypePanel.add(bodyParamsCheckbox);
		
		JButton generateRequestsButton = new JButton("Generate Requests");
		generateRequestsButton.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {

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

				JOptionPane.showMessageDialog(builtInRegexLabel, "Task Complete!");

			}
		});

		JPanel rulesPanel = generateRulesPanel();
		JPanel rulesButtonsPanel = generateRuleButtonsPanel();

		rightPanel.add(generateRequestsTab(requestsTableModel), BorderLayout.CENTER);

		// First row:
        gbc.gridx = 0;
        gbc.gridy = 0;
        
        leftPanel.add(paramLabel,gbc);
       
        gbc.gridy = 1;
        leftPanel.add(parameterPatternTextField,gbc);
        
        
        gbc.gridy = 2;
        leftPanel.add(builtInRegexLabel,gbc);
        
        gbc.gridy = 3;
        leftPanel.add(optionsComboBox,gbc);
        
        
        gbc.gridy = 5;
        leftPanel.add(paramTypeLabel,gbc);
        
        gbc.gridy = 6;
        leftPanel.add(paramTypePanel,gbc);
        
        gbc.gridy = 7;
        leftPanel.add(rulesPanel,gbc);
        
        gbc.gridy = 8;
        leftPanel.add(rulesButtonsPanel,gbc);
        
        gbc.gridy = 9;
		leftPanel.add(generateRequestsButton,gbc);

		configurationTab.add(splitPane, BorderLayout.CENTER);

		return configurationTab;
	}

	private JPanel generateRuleButtonsPanel() {
		JPanel buttonsPanel = new JPanel(new FlowLayout());

		JButton addButton = new JButton("Add");
		
		JButton removeButton = new JButton("Remove");

		addButton.addActionListener(e -> {
			// JWindow popupWindow = new JWindow();
			JDialog popupWindow = new JDialog();

			popupWindow.add(generateRulesPopUpMenu(popupWindow));
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

	private JPanel generateRulesPopUpMenu(JDialog thisDialog) {
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

		UserInterface userInterface = api.userInterface();

		HttpRequestEditor originalRequestViewer = userInterface.createHttpRequestEditor(READ_ONLY);
		HttpRequestEditor modifiedRequestViewer = userInterface.createHttpRequestEditor();
		HttpResponseEditor originalResponseViewer = userInterface.createHttpResponseEditor(READ_ONLY);

		requestsResponsesTabs.addTab("Original Request", originalRequestViewer.uiComponent());
		requestsResponsesTabs.addTab("Modified Request", modifiedRequestViewer.uiComponent());
		requestsResponsesTabs.addTab("Original Response", originalResponseViewer.uiComponent());

		// table of log entries
		JTable table = new JTable(tableModel) {
			@Override
			public void changeSelection(int rowIndex, int columnIndex, boolean toggle, boolean extend) {
				// show the log entry for the selected row

				int modelRow = convertRowIndexToModel(rowIndex);
				AttackCandidate candidate = tableModel.get(modelRow);
				originalRequestViewer.setRequest(candidate.getOriginalRequest());
				modifiedRequestViewer.setRequest(candidate.getModifiedRequest());
				originalResponseViewer.setResponse(candidate.getOriginalResponse());

				super.changeSelection(rowIndex, columnIndex, toggle, extend);
			}
		};

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
		

		JPanel topPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
		JLabel payloadRegexLabel = new JLabel("Payload Regex:");
		JTextField payloadRegexTextField = new JTextField(40);
		payloadRegexTextField.setToolTipText("A regex pattern for fetching payloads");

		JButton generatePayloadsButton = new JButton("Auto Generate Payloads");
		JCheckBox inScopeOnlyCheckbox = new JCheckBox("Search payloads in-scope parameters only");
		inScopeOnlyCheckbox.setSelected(true);

		// ComboBox setup
		JComboBox<String> optionsComboBox = new JComboBox<>();

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

		payloadRegexTextField.setText(".*");

		topPanel.add(payloadRegexLabel);
		topPanel.add(payloadRegexTextField);
		topPanel.add(inScopeOnlyCheckbox);
		topPanel.add(optionsComboBox);
		topPanel.add(generatePayloadsButton);

	
		//payloadsPanel.setLayout(new BorderLayout());
		

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
		JButton generatetAttackButton = new JButton("Generate Attack");

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

			for (AttackCandidate candidate : requestsTableModel.getAllEnabled()) {
				for (int i = 0; i < payloadsList.size(); i++) {

					resultsTableModel.add(candidate.cloneWithPayload(payloadsList.get(i)));
				}

			}

			JOptionPane.showMessageDialog(payloadsPanel, "Task Complete!");
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
		topPanel.setPreferredSize(new Dimension(800,180));
		payloadsPanel.add(topPanel,BorderLayout.NORTH);
		
		JPanel middlePanel = new JPanel();
		middlePanel.setLayout(new BorderLayout());
		
		middlePanel.setPreferredSize(new Dimension(800,300));
		middlePanel.add(listPanel,BorderLayout.CENTER);
		middlePanel.add(controlPanel,BorderLayout.SOUTH);
		
		payloadsPanel.add(middlePanel,BorderLayout.CENTER);
		
		JPanel buttomPanel = new JPanel();
		buttomPanel.setPreferredSize(new Dimension(800,120));
		buttomPanel.add(generatetAttackButton);
		payloadsPanel.add(buttomPanel,BorderLayout.SOUTH);

		
		return payloadsPanel;
	}
}
