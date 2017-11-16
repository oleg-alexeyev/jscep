package org.jscep.server;


import static javax.servlet.http.HttpServletResponse.SC_OK;

import java.util.HashMap;
import java.util.Map;

public final class ScepResponse {
    private int status = SC_OK;
    private Map<String, String> headers = new HashMap<String, String>();
    private byte[] body;
    private String message;

    public void setStatus(int status) {
        this.status = status;
    }

    public int getStatus() {
        return status;
    }

    public void setHeader(String name, String value) {
        headers.put(name, value);
    }

    public Map<String, String> getHeaders() {
        return headers;
    }

    public void setBody(byte[] body) {
        this.body = body;
    }

    public byte[] getBody() {
        return body;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public String getMessage() {
        return message;
    }
}