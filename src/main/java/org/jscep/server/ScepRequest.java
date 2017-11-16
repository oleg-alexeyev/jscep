package org.jscep.server;


import java.util.Map;

public final class ScepRequest {
    private final String method;
    private final byte[] body;
    private final Map<String, String> parameters;

    public ScepRequest(String method, byte[] body, Map<String, String> parameters) {
        this.method = method;
        this.body = body;
        this.parameters = parameters;
    }

    public String getMethod() {
        return method;
    }

    public byte[] getBody() {
        return body;
    }

    public String getParameter(String name) {
        return parameters.get(name);
    }
}