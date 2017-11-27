package org.jscep.transport;

import org.jscep.transport.request.Request;
import org.jscep.transport.response.ScepResponseHandler;

/**
 * Non-clocking SCEP transport.
 */
public interface ScepTransport {
    /**
     * Sends the provided request to the <tt>URL</tt> provided in the
     * constructor.
     * <p>
     * This method will use the provided <tt>ScepResponseHandler</tt> to parse
     * the SCEP server response. If the response can be correctly parsed, this
     * method will pass it to the result handler. Otherwise, this method will
     * pass a <tt>TransportException</tt> to the result handler.
     *
     * @param <T>
     *            the response type.
     * @param msg
     *            the message to send.
     * @param responseHandler
     *            the handler used to parse the response.
     * @param resultHandler
     *            the handler accepting the result or
     *            {@link TransportException}.
     */
    <T> void sendRequest(
            Request msg,
            ScepResponseHandler<T> responseHandler,
            ResultHandler<T> resultHandler
    );
}
