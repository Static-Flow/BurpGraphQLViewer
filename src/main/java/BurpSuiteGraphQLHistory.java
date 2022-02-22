package main.java;

import burp.*;

import javax.swing.*;
import java.awt.*;

/*
This extension collects all previous and future GraphQL requests and displays them in a separate tab for easy viewing.
The graphql requests are grouped by Operation and each request for that operation is shown in a detailed view to the side
which contains the pretty printed GraphQL request, along with the request/response tabs.
 */
public class BurpSuiteGraphQLHistory implements IBurpExtender,
        IExtensionStateListener, ITab {
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        ExtensionState.getInstance().setCallbacks(callbacks);
        ExtensionState.getInstance().setHistoryUI(new HistoryView());
        callbacks.registerExtensionStateListener(this);
        callbacks.addSuiteTab(this);
        callbacks.setExtensionName("BurpSuiteGraphQLHistory");
        callbacks.registerProxyListener(ExtensionState.getInstance().getProxyListener());
        new SwingWorker<Boolean, Void>() {
            @Override
            public Boolean doInBackground() {
                searchExistingHistoryForGraphQLRequests();
                return Boolean.TRUE;
            }
        }.execute();
    }

    //Searches the Target History map for any GraphQL requests that happened before the extension was loaded
    private void searchExistingHistoryForGraphQLRequests() {
        for(IHttpRequestResponse request : ExtensionState.getInstance().getCallbacks().getProxyHistory() ) {
            ExtensionState.getInstance().parseRequestForGraphQLContent(request);
        }
    }

    //Removes the proxy listener and extension tab when the extension is removed
    @Override
    public void extensionUnloaded() {
        ExtensionState.getInstance().getCallbacks().removeProxyListener(ExtensionState.getInstance().getProxyListener());
        ExtensionState.getInstance().getCallbacks().removeSuiteTab(this);
    }

    @Override
    public String getTabCaption() {
        return "GraphQL History";
    }

    @Override
    public Component getUiComponent() {
        return ExtensionState.getInstance().getHistoryUI();
    }
}
