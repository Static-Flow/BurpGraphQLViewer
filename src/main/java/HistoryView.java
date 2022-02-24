package main.java;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;

/*
   This is generated from Jetbrains Intellij SwingDesigner. It sets up the UI code for displaying the GraphQLHistoryEvent Model.
 */
public class HistoryView {
    private JPanel basePanel;
    private JList<String> operationsList;
    private JPanel operationsPanel;
    private JScrollPane operationsListScroller;
    private JPanel operationsVewPanel;
    private JTabbedPane operationsTable;

    public ListModel<String> getOperationsListModel() {
        return operationsList.getModel();
    }

    private void createUIComponents() {
        operationsList = new JList<>();
        operationsList.setModel(new DefaultListModel<>());
        operationsList.addListSelectionListener(e -> updateInViewOperationTable());
    }

    public void updateOperationsTable(String operationName) {
        if (operationsList.getSelectedIndex() != -1 && operationsList.getModel().getElementAt(operationsList.getSelectedIndex()).equals(operationName)) {
            updateInViewOperationTable();
        }
    }

    private void updateInViewOperationTable() {
        new SwingWorker<Boolean, Void>() {
            @Override
            public Boolean doInBackground() {
                operationsTable.removeAll();
                ArrayList<GraphQLHistoryEvent> selectedHistoryEventsByOperation = ExtensionState.getInstance().getGraphQLHistoryEventsMap().get(operationsList.getModel().getElementAt(operationsList.getSelectedIndex()));
                for (int i = 0; i < selectedHistoryEventsByOperation.size(); i++) {
                    operationsTable.addTab(String.valueOf(i), selectedHistoryEventsByOperation.get(i).getDetailedView());
                }
                return Boolean.TRUE;
            }
        }.execute();
    }


    {
// GUI initializer generated by IntelliJ IDEA GUI Designer
// >>> IMPORTANT!! <<<
// DO NOT EDIT OR ADD ANY CODE HERE!
        $$$setupUI$$$();
    }

    /**
     * Method generated by IntelliJ IDEA GUI Designer
     * >>> IMPORTANT!! <<<
     * DO NOT edit this method OR call it in your code!
     *
     * @noinspection ALL
     */
    private void $$$setupUI$$$() {
        createUIComponents();
        basePanel = new JPanel();
        basePanel.setLayout(new BorderLayout(0, 0));
        operationsPanel = new JPanel();
        operationsPanel.setLayout(new BorderLayout(0, 0));
        basePanel.add(operationsPanel, BorderLayout.WEST);
        operationsListScroller = new JScrollPane();
        operationsPanel.add(operationsListScroller, BorderLayout.CENTER);
        operationsList.setMinimumSize(new Dimension(50, 0));
        operationsList.setSelectionMode(0);
        operationsListScroller.setViewportView(operationsList);
        operationsVewPanel = new JPanel();
        operationsVewPanel.setLayout(new BorderLayout(0, 0));
        basePanel.add(operationsVewPanel, BorderLayout.CENTER);
        operationsTable = new JTabbedPane();
        operationsVewPanel.add(operationsTable, BorderLayout.CENTER);
    }

    /**
     * @noinspection ALL
     */
    public JComponent $$$getRootComponent$$$() {
        return basePanel;
    }


}
