package main.java;

import burp.IHttpRequestResponse;
import burp.IInterceptedProxyMessage;
import burp.IProxyListener;

/*
   This class listens to all Proxy traffic and parses responses for whether it is in response to a GraphQL request.
 */
public class ProxyListener implements IProxyListener {

    @Override
    public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage proxyMessage) {
        if (!messageIsRequest) {
            IHttpRequestResponse proxyRequestResponse = proxyMessage.getMessageInfo();
            ExtensionState.getInstance().parseRequestForGraphQLContent(proxyRequestResponse);
        }
    }


}
