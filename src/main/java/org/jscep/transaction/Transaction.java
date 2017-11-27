package org.jscep.transaction;

import java.security.cert.CertStore;

import org.bouncycastle.cms.CMSSignedData;
import org.jscep.message.CertRep;
import org.jscep.message.MessageDecodingException;
import org.jscep.message.MessageEncodingException;
import org.jscep.message.PkiMessage;
import org.jscep.message.PkiMessageDecoder;
import org.jscep.message.PkiMessageEncoder;
import org.jscep.transport.ErrorMappingHandler;
import org.jscep.transport.ResultHandler;
import org.jscep.transport.ResultHolder;
import org.jscep.transport.ScepTransport;
import org.jscep.transport.TransportException;
import org.jscep.transport.request.Request;
import org.jscep.transport.response.PkiOperationResponseHandler;
import org.jscep.util.SignedDataUtils;

/**
 * This class represents an abstract SCEP transaction.
 */
public abstract class Transaction {
    private final PkiMessageEncoder encoder;
    private final PkiMessageDecoder decoder;
    private final ScepTransport transport;

    private State state;
    private FailInfo failInfo;
    private CertStore certStore;

    /**
     * Constructs a new <tt>Transaction</tt>.
     *
     * @param transport
     *            the transport used to conduct the transaction.
     * @param encoder
     *            the encoder used to encode the request.
     * @param decoder
     *            the decoder used to decode the response.
     */
    public Transaction(final ScepTransport transport,
            final PkiMessageEncoder encoder, final PkiMessageDecoder decoder) {
        this.transport = transport;
        this.encoder = encoder;
        this.decoder = decoder;
    }

    /**
     * Retrieve the reason for failure.
     * <p>
     * If the transaction did not fail, this method throws an
     * {@link IllegalStateException}.
     *
     * @return the reason for failure.
     */
    public final FailInfo getFailInfo() {
        if (state != State.CERT_NON_EXISTANT) {
            throw new IllegalStateException(
                    "No failure has been received.  Check state!");
        }
        return failInfo;
    }

    /**
     * Retrieve the <tt>CertStore</tt> sent by the SCEP server.
     * <p>
     * If the transaction did not succeed, this method throws an
     * {@link IllegalStateException}
     *
     * @return the <tt>CertStore</tt>
     */
    public final CertStore getCertStore() {
        if (state != State.CERT_ISSUED) {
            throw new IllegalStateException(
                    "No certstore has been received.  Check state!");
        }
        return certStore;
    }

    /**
     * Sends the request and processes the server response.
     *
     * @return the state as returned by the SCEP server.
     * @throws TransactionException
     *             if an error was encountered when sending this transaction.
     */
    public State send() throws TransactionException {
        ResultHolder<State, TransactionException> holder =
                new ResultHolder<State, TransactionException>
                        (TransactionException.class);
        send(holder);
        return holder.getResult();
    }

    /**
     * Sends the request and processes the server response.
     *
     * @return the state as returned by the SCEP server.
     * @throws TransactionException
     *             if an error was encountered when sending this transaction.
     */
    public abstract void send(ResultHandler<State> handler);

    /**
     * Returns the ID of this transaction.
     *
     * @return the ID of this transaction.
     */
    public abstract TransactionId getId();

    final void send(final PkiOperationResponseHandler responseHandler,
            final Request req, final ResultHandler<CMSSignedData> handler) {
        transport.sendRequest(req, responseHandler,
                new TransactionErrorMappingHandler<CMSSignedData>(handler));
    }

    final PkiMessage<?> decode(final CMSSignedData res)
            throws MessageDecodingException {
        return decoder.decode(res);
    }

    final CMSSignedData encode(final PkiMessage<?> message)
            throws MessageEncodingException {
        return encoder.encode(message);
    }

    final State pending() {
        this.state = State.CERT_REQ_PENDING;
        return state;
    }

    final State failure(final FailInfo failInfo) {
        this.failInfo = failInfo;
        this.state = State.CERT_NON_EXISTANT;

        return state;
    }

    final State success(final CertStore certStore) {
        this.certStore = certStore;
        this.state = State.CERT_ISSUED;

        return state;
    }

    final CertStore extractCertStore(final CertRep response) {
        CMSSignedData signedData = response.getMessageData();

        return SignedDataUtils.fromSignedData(signedData);
    }

    /**
     * This class represents the state of a transaction.
     */
    public enum State {
        /**
         * The transaction is a pending state.
         */
        CERT_REQ_PENDING,
        /**
         * The transaction is in a failed state.
         * 
         * Clients should use {@link Transaction#getFailInfo()} to retrieve the
         * failure reason.
         */
        CERT_NON_EXISTANT,
        /**
         * The transaction has succeeded.
         *
         * Clients should use {@link Transaction#getCertStore()} to retrieve the
         * enrolled certificates.
         */
        CERT_ISSUED,
    }

    static final class TransactionErrorMappingHandler<T>
            extends ErrorMappingHandler<T> {

        TransactionErrorMappingHandler(ResultHandler<T> responseHandler) {
            super(responseHandler);
        }

        @Override
        protected Throwable mapError(Throwable e) {
            if (e instanceof TransportException) {
                return e;
            }
            return new TransactionException(e);
        }
    }
}
