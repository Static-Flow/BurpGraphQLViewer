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
        2. Try and extract the optional query parameters containing the query, and operationName.
        3. Check the request method and parse the request accordingly
            3-A. If the method is GET, either take the "operationName" from the query params or parse the "query" param for it
            3-B. If the method is POST and includes query params but NOT "Content-Type: application/graphql" parse like 3-A, else parse message body for "operationName"
        4. If an "operationName" was found, add it to the GraphQL history map.
     */
    public void parseRequestForGraphQLContent(IHttpRequestResponse proxyRequestResponse) {
        IRequestInfo requestInfo = ExtensionState.getInstance().getCallbacks().getHelpers().analyzeRequest(proxyRequestResponse);
        //If url for request is a graphql endpoint
        if (requestInfo.getUrl().getPath().contains("graphql")) {
            getCallbacks().printOutput("Found GraphQL request for host " + proxyRequestResponse.getHttpService().getHost());
            String operationName = "";
            String query = "";
            //Try and extract our parameters if they exist
            for (IParameter p : requestInfo.getParameters()) {
                switch (p.getName()) {
                    case "query":
                        query = getCallbacks().getHelpers().urlDecode(p.getValue());
                        break;
                    case "operationName":
                        operationName = p.getValue();
                        break;
                    default:
                        //ignore any other query params
                        break;
                }
            }
            //Extraction of the GraphQL query is different based on POST vs GET reqs
            switch (requestInfo.getMethod()) {
                case "GET":
                    /*
                        If it's GET, we may have everything we need already from query params. But "operationName"
                        isn't required so if we get here and "operationName" is empty we need to decipher the "operationName" from the query body.
                        Also of note, if "operationName" is empty then by the spec def there should only be 1 operation.
                     */
                    if (operationName.length() == 0) {
                        //Add our GraphQL Event to the history
                        operationName = parseGraphQLGetRequest(query);
                    }
                    break;
                case "POST":
                    /*
                        If it's POST, we need to extract it from the message body. But we also need to handle two extra cases:
                            1. If the "query" query string parameter is present (as in the GET example above), it should be parsed and handled
                             in the same way as the HTTP GET case.
                            2. If the "application/graphql" Content-Type header is present, treat the HTTP POST body contents as the GraphQL query string.

                        POST works much like GET except we need to extract the query from the message body. Then to get the operation name
                     */

                    // If we have a query parameter set and the Content-Type is NOT `"application/graphql"` we treat it like a GET request
                    if (query.length() != 0 && !String.valueOf(requestInfo.getContentType()).equals("application/graphql")) {
                        operationName = parseGraphQLGetRequest(query);
                    } else {
                        //find out body offset in the request
                        int offset = getCallbacks().getHelpers().analyzeRequest(proxyRequestResponse).getBodyOffset();
                        /*
                        Here there be small dragons. We don't know the GraphQL spec, so it can't be unmarshalled into a POJO. Instead, we unmarshal to a
                        generic Map which is fine since the two values we want, "operationName", and "query", are always strings. Once we have the map
                        we use the shiny new `computeIfAbsent` to determine if "operationName" was set. If it isn't, we "compute" the value using the
                        "query" field that is always there the same way for "GET" requests.
                         */
                        Map o = getBuilder().create().fromJson(
                                Arrays.toString(Arrays.copyOfRange(proxyRequestResponse.getRequest(), offset, proxyRequestResponse.getRequest().length)), Map.class);
                        operationName = (String) o.computeIfAbsent("operationName", k -> parseGraphQLGetRequest((String) o.get("query")));
                    }

                    break;
                default:
                    ExtensionState.getInstance().getCallbacks().printError("Invalid GraphQL HTTP Method");
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
