package main.java;

import burp.IHttpService;
import burp.IMessageEditorController;

//This stub is needed for enabling "right click send to Repeater/Intruder/etc" from within the GraphQLHistoryEvent detailed view
public class MessageEditorController implements IMessageEditorController {

    private final IHttpService service;
    private final byte[] request;
    private final byte[] response;

    public MessageEditorController(IHttpService service, byte[] request, byte[] response) {
        this.service = service;
        this.request = request;
        this.response = response;
    }

    @Override
    public IHttpService getHttpService() {
        return service;
    }

    @Override
    public byte[] getRequest() {
        return request;
    }

    @Override
    public byte[] getResponse() {
        return response;
    }
}
