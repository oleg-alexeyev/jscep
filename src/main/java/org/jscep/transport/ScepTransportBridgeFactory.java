package org.jscep.transport;


import java.net.URL;

import org.jscep.client.ScepClient;
import org.jscep.transport.request.Request;
import org.jscep.transport.response.ScepResponseHandler;

/**
 * {@link ScepTransportFactory} which uses {@link TransportFactory}
 * and provides {@link ScepClient} with {@link ScepTransport} implementation
 * over {@link Transport}.
 */
public class ScepTransportBridgeFactory implements ScepTransportFactory {

    private final TransportFactory factory;

    public ScepTransportBridgeFactory(TransportFactory factory) {
        this.factory = factory;
    }

    @Override
    public ScepTransport forMethod(TransportFactory.Method method, URL url) {
        final Transport transport = factory.forMethod(method, url);
        return new ScepTransport() {
            @Override
            public <T> void sendRequest(
                    Request msg,
                    ScepResponseHandler<T> responseHandler,
                    ResultHandler<T> resultHandler
            ) {
                try {
                    T result = transport.sendRequest(msg, responseHandler);
                    resultHandler.handle(result, null);
                } catch (TransportException e) {
                    resultHandler.handle(null, e);
                }
            }
        };
    }
}