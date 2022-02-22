package main.java;

import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IParameter;
import burp.IRequestInfo;
import com.google.gson.GsonBuilder;
import graphql.language.Field;
import graphql.language.OperationDefinition;
import graphql.parser.Parser;

import javax.swing.*;
import java.awt.*;
import java.util.*;


/*
Static singleton class for keeping extension state.
 */
public class ExtensionState {

    //reference to this state object
    private static ExtensionState                                   state = null;
    //reference to the Burp callbacks
    private IBurpExtenderCallbacks                                  callbacks;
    //map of all GraphQL requests, keys are "Operations", values are the request data
    private final HashMap<String, ArrayList<GraphQLHistoryEvent>>   graphQLHistoryEvents;
    //JSON lib for handling GraphQL request parsing
    private final GsonBuilder                                       builder;
    //reference to the Burp Proxy Listener that catches GraphQL requests
    private final ProxyListener                                     httpProxyListener;
    //reference to this extensions custom Tab UI
    private HistoryView                                             historyUI;


    private ExtensionState() {
        graphQLHistoryEvents = new HashMap<>();
        builder = new GsonBuilder();
        httpProxyListener = new ProxyListener();

    }

    public static ExtensionState getInstance() {
        if (state == null)
            state = new ExtensionState();
        return state;
    }

    public GsonBuilder getBuilder() {
        return builder;
    }

    public IBurpExtenderCallbacks getCallbacks() {
        return callbacks;
    }

    public void setCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
    }

    public Map<String,ArrayList<GraphQLHistoryEvent>> getGraphQLHistoryEventsMap() {
        return graphQLHistoryEvents;
    }

    /*
       Inserts a new GraphQL requests into the map of current GraphQL requests
     */
    public void addEventToGraphQLHistoryEventsMap(GraphQLHistoryEvent event, String operationName) {
        //if we have seen this operation before append the new event, else create a new entry with the new event
        ArrayList<GraphQLHistoryEvent> operationEvents = graphQLHistoryEvents.computeIfAbsent(operationName, k -> new ArrayList<>());
        operationEvents.add(event);
        if( operationEvents.size() == 1) {
            ((DefaultListModel<String>)historyUI.getOperationsListModel()).addElement(operationName);
        } else {
            historyUI.updateOperationsTable(operationName);
        }
    }

    public ProxyListener getProxyListener() {
        return httpProxyListener;
    }

    public Component getHistoryUI() {
        return historyUI.$$$getRootComponent$$$();
    }

    public void setHistoryUI(HistoryView historyUI) {
        this.historyUI = historyUI;
    }

    /*
     This method extracts the operation name from the GraphQL query body by first checking is the "operationName" field is set and if not, uses the first
     statement selection as the operation name.
     */
    private String parseGraphQLGetRequest(String query) {
        OperationDefinition operation;
        try {
            //Attempt to parse the GraphQL query
            operation = (OperationDefinition) (new Parser().parseDocument(query).getDefinitions().get(0));
            //check if "operationName" is not set, get the name of the first selection
            if (operation.getName() == null || Objects.equals(operation.getName(), "")) {
                return ((Field) operation.getSelectionSet().getSelections().get(0)).getName();
            } else {
                //return the "operationName"
                return operation.getName();
            }
        } catch (Exception e) {
            getCallbacks().printError(e.getMessage());
            return "";
        }
    }

    /*
    Parse potential Proxy Request to determine if it's a GraphQL request following the steps below:
        1. Check if the URL contains the string "graphql" (This may be lossy or over-zealous) There's no universal GraphQL endpoint scheme
        2. Try and extract the query and operationName from the request.
        3. Parse the query if the "operationName" is not set.
        4. If an "operationName" was found, add it to the GraphQL history map.
     */
    public void parseRequestForGraphQLContent(IHttpRequestResponse proxyRequestResponse) {
        IRequestInfo requestInfo = ExtensionState.getInstance().getCallbacks().getHelpers().analyzeRequest(proxyRequestResponse);
        //If url for request is a graphql endpoint
        if (requestInfo.getUrl().toString().contains("graphql")) {
            String operationName = "";
            String query = "";
            //Try and extract our parameters if they exist
            for (IParameter p : requestInfo.getParameters()) {
                switch (p.getName()) {
                    case "query":
                        query = getCallbacks().getHelpers().urlDecode(p.getValue()).replaceAll("\\\\n","");
                        break;
                    case "operationName":
                        operationName = p.getValue();
                        break;
                    default:
                        //ignore any other query params
                        break;
                }
            }

            if (query.length() == 0) {
                //If the query is empty this is probably not a GraphQL request.
                return;
            }

            //Burp parses the JSON literal `null` as the string "null" so we have to check for that here
            if (operationName.length() == 0 || operationName.equals("null")) {
                //If the operationName isn't provided the query is parsed to find it
                operationName = parseGraphQLGetRequest(query);
            }

            if( operationName.length() != 0 ) {
                addEventToGraphQLHistoryEventsMap(
                        new GraphQLHistoryEvent(
                                proxyRequestResponse,
                                query
                        ),
                        operationName
                );
            }
        }
    }
}
