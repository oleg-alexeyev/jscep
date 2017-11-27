package org.jscep.transport;

import java.net.URL;

import org.jscep.transport.TransportFactory.Method;

/**
 * Factory for non-clocking SCEP transports.
 */
public interface ScepTransportFactory {

    ScepTransport forMethod(Method method, URL url);
}
