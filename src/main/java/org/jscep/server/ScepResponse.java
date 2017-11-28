package org.jscep.server;


import static java.util.Collections.singletonList;
import static javax.servlet.http.HttpServletResponse.SC_OK;

import java.nio.charset.Charset;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public final class ScepResponse {
    private int status = SC_OK;
    private Map<String, String> headers = new HashMap<String, String>();
    private byte[] body;

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

    public Map<String, List<String>> getMultiValueHeaders() {
        Map<String, List<String>> h = new HashMap<String, List<String>>();
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            h.put(entry.getKey(), singletonList(entry.getValue()));
        }
        return h;
    }

    public void setBody(byte[] body) {
        this.body = body;
    }

    public void setMessage(String message) {
        this.body = message.getBytes(Charset.forName("UTF-8"));
    }

    public byte[] getBody() {
        return body;
    }
}