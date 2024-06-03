package cybenari;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import cybenari.models.AutoIntruderTab;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;
import cybenari.models.RequestsTableModel;
import cybenari.models.ResultsTableModel;

import javax.swing.*;
import java.awt.*;

import java.net.MalformedURLException;

import static burp.api.montoya.ui.editor.EditorOptions.READ_ONLY;

public class AutoIntruder implements BurpExtension {

	private MontoyaApi api;
	private boolean engineStopped = false;
	private int tabCounter = 1;
	private RequestsTableModel requestsTableModel;
	private ResultsTableModel resultsTableModel;

	RequestSendingManager sendingManager;

	public static void main(String[] args) throws MalformedURLException {

	}

	public void initialize(MontoyaApi api) {
		this.api = api;

		// set extension name
		api.extension().setName("AutoIntruder");

		Logging logging = api.logging();

		logging.logToOutput("Loaded Succesfully...");

		// AnalysisEngine analysisEngine = new AnalysisEngine(logging);

		requestsTableModel = new RequestsTableModel(logging);
		resultsTableModel = new ResultsTableModel(logging);
		this.sendingManager = new RequestSendingManager(resultsTableModel, api);

		api.userInterface().registerSuiteTab("AutoIntruder",
				constructLoggerTab(requestsTableModel, logging, resultsTableModel));

		// MatchRule defaultRule = new MatchRule();
		// api.http().registerHttpHandler(new httpHandler(api, analysisEngine,
		// requestsTableModel, defaultRule));

	}

	private Component constructLoggerTab(RequestsTableModel requestsTableModel, Logging logging,
			ResultsTableModel resultsTableModel) {

		JPanel mainPanel = new JPanel();
		mainPanel.setLayout(new BorderLayout(0, 0));

		JPanel tabsAndButtonPanel = new JPanel();
		tabsAndButtonPanel.setLayout(new BorderLayout(0, 0));

		JTabbedPane tabbedPane = new JTabbedPane();

		JPanel addButtonLayout = new JPanel();
		
		
		
		JPanel addTabPanel = new JPanel();
		
		tabbedPane.addTab(String.valueOf(this.tabCounter), new AutoIntruderTab(api));
		tabbedPane.addTab("+", addTabPanel);
		

		tabsAndButtonPanel.add(addButtonLayout);
		tabsAndButtonPanel.add(tabbedPane);
		mainPanel.add(tabsAndButtonPanel);
		
	
		tabbedPane.addChangeListener(new ChangeListener() {
            @Override
            public void stateChanged(ChangeEvent e) {
            	JTabbedPane sourceTabbedPane = (JTabbedPane) e.getSource();
                int selectedIndex = sourceTabbedPane.getSelectedIndex();
                if (selectedIndex == sourceTabbedPane.getTabCount() - 1) {


                	sourceTabbedPane.addTab(String.valueOf(tabbedPane.getTabCount()), new AutoIntruderTab(api));
                	sourceTabbedPane.addTab("+",new JPanel());
                	sourceTabbedPane.setSelectedIndex(sourceTabbedPane.getTabCount() - 2);
                	sourceTabbedPane.removeTabAt(selectedIndex);
                	
        			
        			
                }
            }
        });

		return mainPanel;
	}



}
