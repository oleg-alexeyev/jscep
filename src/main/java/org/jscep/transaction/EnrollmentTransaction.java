package org.jscep.transaction;

import static org.slf4j.LoggerFactory.getLogger;

import java.io.IOException;
import java.security.spec.InvalidKeySpecException;

import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.jscep.asn1.IssuerAndSubject;
import org.jscep.message.CertRep;
import org.jscep.message.GetCertInitial;
import org.jscep.message.MessageDecodingException;
import org.jscep.message.MessageEncodingException;
import org.jscep.message.PkcsReq;
import org.jscep.message.PkiMessage;
import org.jscep.message.PkiMessageDecoder;
import org.jscep.message.PkiMessageEncoder;
import org.jscep.message.PkiRequest;
import org.jscep.transport.ErrorDelegatingHandler;
import org.jscep.transport.ResultHandler;
import org.jscep.transport.ScepTransport;
import org.jscep.transport.request.PkiOperationRequest;
import org.jscep.transport.response.PkiOperationResponseHandler;
import org.jscep.util.CertificationRequestUtils;
import org.slf4j.Logger;

/**
 * This class represents a SCEP enrollment <tt>Transaction</tt>.
 * 
 * @see PkcsReq
 * @see GetCertInitial
 */
public final class EnrollmentTransaction extends Transaction {
    private static final Logger LOGGER = getLogger(EnrollmentTransaction.class);
    private static final NonceQueue QUEUE = new NonceQueue();
    private final TransactionId transId;
    private final PkiRequest<?> request;

    /**
     * Constructs a new transaction for enrollment request.
     * 
     * @param transport
     *            the transport to use to send the transaction request.
     * @param encoder
     *            the encoder to encode the transaction request.
     * @param decoder
     *            the decoder to decode the transaction response.
     * @param csr
     *            the signing request to send.
     * @throws TransactionException
     *             if there is a problem creating the transaction ID.
     */
    public EnrollmentTransaction(final ScepTransport transport,
            final PkiMessageEncoder encoder, final PkiMessageDecoder decoder,
            final PKCS10CertificationRequest csr) throws TransactionException {
        super(transport, encoder, decoder);
        try {
            this.transId = TransactionId.createTransactionId(
                    CertificationRequestUtils.getPublicKey(csr), "SHA-1");
        } catch (IOException e) {
            throw new TransactionException(e);
        } catch (InvalidKeySpecException e) {
            throw new TransactionException(e);
        }
        this.request = new PkcsReq(transId, Nonce.nextNonce(), csr);
    }

    /**
     * Constructs a new transaction for a enrollment poll request.
     * 
     * @param transport
     *            the transport to use to send the transaction request.
     * @param encoder
     *            the encoder to encode the transaction request.
     * @param decoder
     *            the decoder to decode the transaction response.
     * @param ias
     *            the issuer and subject to send.
     * @param transId
     *            the transaction ID to use.
     */
    public EnrollmentTransaction(final ScepTransport transport,
            final PkiMessageEncoder encoder, final PkiMessageDecoder decoder,
            final IssuerAndSubject ias, final TransactionId transId) {
        super(transport, encoder, decoder);

        this.transId = transId;
        this.request = new GetCertInitial(transId, Nonce.nextNonce(), ias);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public TransactionId getId() {
        return transId;
    }

    /**
     * Sends the request to the SCEP server and processes the response.
     *
     * @param handler the handler accepting a {@link State}
     *                or {@link TransactionException} if an error occurs.
     */
    @Override
    public void send(final ResultHandler<State> handler) {
        CMSSignedData signedData;
        try {
            signedData = encode(request);
        } catch (MessageEncodingException e) {
            handler.handle(null, new TransactionException(e));
            return;
        }
        LOGGER.debug("Sending {}", signedData);
        PkiOperationResponseHandler resHandler =
                new PkiOperationResponseHandler();
        send(resHandler,
                new PkiOperationRequest(signedData),
                new TransactionErrorMappingHandler<CMSSignedData>(
                        new ErrorDelegatingHandler<CMSSignedData>(handler) {
                            @Override
                            protected void doHandle(CMSSignedData res) {
                                handleResponse(res, handler);
                            }
                        }
                )
        );
    }

    private void handleResponse(CMSSignedData res, ResultHandler<State> handler) {
        LOGGER.debug("Received response {}", res);

        CertRep response;
        try {
            response = (CertRep) decode(res);
        } catch (MessageDecodingException e) {
            handler.handle(null, new TransactionException(e));
            return;
        }
        if (validateExchange(request, response, handler)) {
            LOGGER.debug("Response: {}", response);
            if (response.getPkiStatus() == PkiStatus.FAILURE) {
                handler.handle(failure(response.getFailInfo()), null);
            } else if (response.getPkiStatus() == PkiStatus.SUCCESS) {
                handler.handle(success(extractCertStore(response)), null);
            } else {
                handler.handle(pending(), null);
            }
        }
    }

    private boolean validateExchange(
            final PkiMessage<?> req,
            final CertRep res,
            final ResultHandler<?> handler
    )
            {
        LOGGER.debug("Validating SCEP message exchange");

        if (!res.getTransactionId().equals(req.getTransactionId())) {
            handler.handle(null,
                    new TransactionException("Transaction ID mismatch"));
            return false;
        } else {
            LOGGER.debug("Matched transaction IDs");
        }

        // The requester SHOULD verify that the recipientNonce of the reply
        // matches the senderNonce it sent in the request.
        if (!res.getRecipientNonce().equals(req.getSenderNonce())) {
            handler.handle(null, new InvalidNonceException
                    (req.getSenderNonce(), res.getRecipientNonce()));
            return false;
        } else {
            LOGGER.debug("Matched request senderNonce and response recipientNonce");
        }

        if (res.getSenderNonce() == null) {
            LOGGER.warn("Response senderNonce is null");
            return true;
        }

        // http://tools.ietf.org/html/draft-nourse-scep-20#section-8.5
        // Check that the nonce has not been encountered before.
        if (QUEUE.contains(res.getSenderNonce())) {
            handler.handle(null, new InvalidNonceException
                    (res.getSenderNonce()));
            return false;
        } else {
            QUEUE.add(res.getSenderNonce());
            LOGGER.debug("{} has not been encountered before",
                    res.getSenderNonce());
        }

        LOGGER.debug("SCEP message exchange validated successfully");
        return true;
    }
}
