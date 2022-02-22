package main.java;

import burp.IHttpRequestResponse;
import burp.IMessageEditor;
import graphql.language.AstPrinter;
import graphql.parser.Parser;

import javax.swing.*;
import java.awt.*;


/*
   This class represents a GraphQL request that was found in the Target History or detected via the Proxy Listener
 */
public class GraphQLHistoryEvent {
    //The Burp request/response pair
    private final IHttpRequestResponse               graphQLQueryRequestResponse;
    //The extracted GraphQL query
    private final String                             graphQLQuery;
    //The detailed view component for viewing this GraphQL Event
    private final Component                          detailedView;


    public GraphQLHistoryEvent(IHttpRequestResponse graphQLQueryRequestResponse, String graphQLQuery) {
        this.graphQLQueryRequestResponse = graphQLQueryRequestResponse;
        this.graphQLQuery = graphQLQuery;
        this.detailedView = buildDetailedView();
    }

    /*
       The event detailed view consists of a pretty printed text area containing the GraphQL query and the Request/Response Burp view like in Repeater tabs.
     */
    private Component buildDetailedView() {
        JSplitPane operationDetailView = new JSplitPane();
        operationDetailView.setDividerLocation(0.5);
        JTextArea graphQLQueryText = new JTextArea(AstPrinter.printAst(new Parser().parseDocument(graphQLQuery)));
        graphQLQueryText.setEditable(false);
        operationDetailView.setLeftComponent(graphQLQueryText);
        JTabbedPane requestResponseEditors = new JTabbedPane();
        IMessageEditor requestEditor = ExtensionState.getInstance().getCallbacks().createMessageEditor(
                new MessageEditorController(
                        graphQLQueryRequestResponse.getHttpService(),
                        graphQLQueryRequestResponse.getRequest(),
                        graphQLQueryRequestResponse.getResponse()
                ),
                true);
        requestEditor.setMessage(graphQLQueryRequestResponse.getRequest(),true);
        requestResponseEditors.addTab("Request",requestEditor.getComponent());
        IMessageEditor responseEditor = ExtensionState.getInstance().getCallbacks().createMessageEditor(
                new MessageEditorController(
                        graphQLQueryRequestResponse.getHttpService(),
                        graphQLQueryRequestResponse.getRequest(),
                        graphQLQueryRequestResponse.getResponse()
                ),
                true);
        responseEditor.setMessage(graphQLQueryRequestResponse.getResponse(),false);
        requestResponseEditors.addTab("Response",responseEditor.getComponent());
        operationDetailView.setRightComponent(requestResponseEditors);
        return operationDetailView;
    }

    @Override
    public String toString() {
        return "GraphQLHistoryEvent{" +
                ", graphQLQueryRequestResponse=" + graphQLQueryRequestResponse +
                ", graphQLQuery='" + graphQLQuery + '\'' +
                '}';
    }

    public Component getDetailedView() {
        return detailedView;
    }
}


