package main.java;

import burp.IHttpRequestResponse;
import burp.IInterceptedProxyMessage;
import burp.IProxyListener;

import javax.swing.*;

/*
   This class listens to all Proxy traffic and parses responses for whether it is in response to a GraphQL request.
 */
public class ProxyListener implements IProxyListener {

    @Override
    public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage proxyMessage) {
        new SwingWorker<Boolean, Void>() {
            @Override
            public Boolean doInBackground() {
                /*
                    We only want to trigger on responses for 2 reasons:
                        1. There's no need to record GraphQL Requests that never get a response from the server
                        2. Responses will have the fully hydrated `IHttpRequestResponse` object which is useful for showing in the UI
                 */
                if ( messageIsRequest == false ) {
                    IHttpRequestResponse proxyRequestResponse = proxyMessage.getMessageInfo();
                    ExtensionState.getInstance().parseRequestForGraphQLContent(proxyRequestResponse);
                }
                return Boolean.TRUE;
            }
        }.execute();

    }


}
