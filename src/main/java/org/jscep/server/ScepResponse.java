package org.jscep.server;


import static java.util.Collections.singletonList;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public final class ScepResponse {
    private final int status;
    private final Map<String, String> headers;
    private final byte[] body;

    public ScepResponse(int status, Map<String, String> headers, byte[] body) {
        this.status = status;
        this.headers = headers;
        this.body = body;
    }

    public int getStatus() {
        return status;
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

    public byte[] getBody() {
        return body;
    }
}