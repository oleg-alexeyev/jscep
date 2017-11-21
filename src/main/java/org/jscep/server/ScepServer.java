/*
 * Copyright (c) 2009-2010 David Grant
 * Copyright (c) 2010 ThruPoint Ltd
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package org.jscep.server;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CRLException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import javax.servlet.http.HttpServletResponse;

import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCRLStore;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSAbsentContent;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.SignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.DecoderException;
import org.jscep.asn1.IssuerAndSubject;
import org.jscep.message.CertRep;
import org.jscep.message.MessageDecodingException;
import org.jscep.message.MessageEncodingException;
import org.jscep.message.PkcsPkiEnvelopeDecoder;
import org.jscep.message.PkcsPkiEnvelopeEncoder;
import org.jscep.message.PkiMessage;
import org.jscep.message.PkiMessageDecoder;
import org.jscep.message.PkiMessageEncoder;
import org.jscep.transaction.FailInfo;
import org.jscep.transaction.MessageType;
import org.jscep.transaction.Nonce;
import org.jscep.transaction.OperationFailureException;
import org.jscep.transaction.TransactionId;
import org.jscep.transport.request.Operation;
import org.jscep.transport.response.Capability;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * <p>This class implements SCEP server logic.</p>
 *
 * <p>{@link #service(ScepRequest, ScepResponse)} method is the entry point.
 * It accepts the request, decodes the operation and corresponding data
 * and calls {@link CertificateAuthority} methods implementing the operation.
 * </p>
 *
 * <p>{@link ScepResponse} will be filled with encoded response by
 * a {@link ScepResponseBuilder} when {@link CertificateAuthority} completes
 * the operation and calls the builder.</p>
 */
public class ScepServer {
    private static final String GET = "GET";
    private static final String POST = "POST";
    private static final String MSG_PARAM = "message";
    private static final String OP_PARAM = "operation";
    private static final Logger LOGGER = LoggerFactory
            .getLogger(ScepServer.class);

    private final CertificateAuthority ca;

    public ScepServer(CertificateAuthority ca) {
        this.ca = ca;
    }

    public final void service(ScepRequest req, ScepResponse res) {
        ResponseBuilder builder = new ResponseBuilder(res);

        Operation op;
        try {
            op = getOperation(req);
            if (op == null) {
                builder.badRequest("Missing \"operation\" parameter.");
                return;
            }
        } catch (IllegalArgumentException e) {
            builder.badRequest("Invalid \"operation\" parameter.");
            return;
        }

        String reqMethod = req.getMethod();
        if (op == Operation.PKI_OPERATION) {
            if (!reqMethod.equals(POST) && !reqMethod.equals(GET)) {
                builder.methodNotAllowed(reqMethod, op, GET, POST);
                return;
            }
        } else if (!reqMethod.equals(GET)) {
            builder.methodNotAllowed(reqMethod, op, GET);
            return;
        }

        try {
            switch (op) {
                case GET_CA_CAPS:
                    ca.getCapabilities(req.getParameter(MSG_PARAM), builder);
                    break;
                case GET_CA_CERT:
                    ca.getCaCertificate(req.getParameter(MSG_PARAM), builder);
                    break;
                case GET_NEXT_CA_CERT:
                    ca.getNextCaCertificate(req.getParameter(MSG_PARAM), builder);
                    break;
                case PKI_OPERATION:
                    doPkiOperation(req, builder);
                    break;
                default:
                    builder.badRequest("Unknown operation");
                    break;
            }
        } catch (Throwable e) {
            builder.error(e);
        }
    }

    private Operation getOperation(final ScepRequest req) {
        String op = req.getParameter(OP_PARAM);
        if (op == null) {
            return null;
        }
        return Operation.forName(req.getParameter(OP_PARAM));
    }

    private void doPkiOperation(ScepRequest req, ResponseBuilder builder)
    throws Exception {
        byte[] body;
        if (req.getMethod().equals(POST)) {
            body = req.getBody();
        } else {
            String msg = req.getParameter(MSG_PARAM);
            if (msg == null || msg.length() == 0) {
                builder.badRequest("Missing \"message\" parameter.");
                return;
            }
            try {
                body = Base64.decode(msg);
            } catch (DecoderException e) {
                builder.badRequest("Incorrectly encoded \"message\" " +
                        "parameter.");
                return;
            }
        }

        CMSSignedData sd = new CMSSignedData(body);

        Store reqStore = sd.getCertificates();
        Collection<X509CertificateHolder> reqCerts = reqStore
                .getMatches(null);

        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        X509CertificateHolder holder = reqCerts.iterator().next();
        ByteArrayInputStream bais = new ByteArrayInputStream(
                holder.getEncoded()
        );
        X509Certificate reqCert;
        try {
            reqCert = (X509Certificate) factory.generateCertificate(bais);
        } catch (CertificateException e) {
            builder.badRequest("Incorrectly encoded certificate.", e);
            return;
        }
        builder.setRequestCertificate(reqCert);

        PkiMessage<?> msg;
        try {
            PkcsPkiEnvelopeDecoder envDecoder = new PkcsPkiEnvelopeDecoder(
                    ca.getRecipient(), ca.getRecipientKey());
            PkiMessageDecoder decoder = new PkiMessageDecoder(reqCert,
                    envDecoder);
            msg = decoder.decode(sd);
        } catch (MessageDecodingException e) {
            builder.badRequest("Incorrectly encoded request.", e);
            return;
        }

        MessageType msgType = msg.getMessageType();
        Object msgData = msg.getMessageData();

        TransactionId transId = msg.getTransactionId();
        builder.setTransactionId(transId);
        builder.setSenderNonce(Nonce.nextNonce());
        builder.setRecipientNonce(msg.getSenderNonce());

        switch (msgType) {
            case GET_CERT: {
                IssuerAndSerialNumber iasn = (IssuerAndSerialNumber) msgData;
                X500Name issuer = iasn.getName();
                BigInteger serial = iasn.getSerialNumber().getValue();
                ca.getCert(issuer, serial, builder);
                break;
            }
            case GET_CERT_INITIAL: {
                IssuerAndSubject ias = (IssuerAndSubject) msgData;
                X500Name issuer = X500Name.getInstance(ias.getIssuer());
                X500Name subject = X500Name.getInstance(ias.getSubject());
                ca.getCertInitial(issuer, subject, transId, builder);
                break;
            }
            case GET_CRL: {
                IssuerAndSerialNumber iasn = (IssuerAndSerialNumber) msgData;
                X500Name issuer = iasn.getName();
                BigInteger serialNumber = iasn.getSerialNumber().getValue();
                ca.getCrl(issuer, serialNumber, builder);
                break;
            }
            case PKCS_REQ:
                PKCS10CertificationRequest certReq = (PKCS10CertificationRequest) msgData;
                ca.enrol(certReq, reqCert, transId, builder);
                break;
            default:
                throw new RuntimeException("Unknown message type: " +
                        msgType);
        }
    }

    private final class ResponseBuilder implements ScepResponseBuilder {
        private final ScepResponse res;
        private Nonce senderNonce;
        private Nonce recipientNonce;
        private TransactionId transId;
        private X509Certificate reqCert;

        ResponseBuilder(ScepResponse res) {
            this.res = res;
        }

        @Override
        public void capabilities(Set<Capability> caps) {
            res.setHeader("Content-Type", "text/plain");
            StringBuilder builder = new StringBuilder();
            for (Capability cap : caps) {
                builder.append(cap.toString());
                builder.append('\n');
            }
            res.setMessage(builder.toString());
        }

        @Override
        public void caCertificate(List<X509Certificate> certs) {
            try {
                if (certs.size() == 0) {
                    res.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
                    res.setMessage("GetCaCert failed to obtain CA from store");
                } else if (certs.size() == 1) {
                    res.setHeader("Content-Type", "application/x-x509-ca-cert");
                    res.setBody(certs.get(0).getEncoded());
                } else {
                    CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
                    JcaCertStore store = new JcaCertStore(certs);
                    generator.addCertificates(store);
                    CMSSignedData degenerateSd = generator.generate(
                            new CMSAbsentContent()
                    );
                    res.setHeader("Content-Type", "application/x-x509-ca-ra-cert");
                    res.setBody(degenerateSd.getEncoded());
                }
            } catch (CertificateEncodingException e) {
                error(e);
            } catch (CMSException e) {
                error(e);
            } catch (IOException e) {
                error(e);
            }
        }

        @Override
        public void nextCaCertificate(List<X509Certificate> certs) {
            try {
                if (certs.size() == 0) {
                    res.setStatus(HttpServletResponse.SC_NOT_IMPLEMENTED);
                    res.setMessage("GetNextCACert is not supported");
                } else {
                    res.setHeader("Content-Type", "application/x-x509-next-ca-cert");
                    CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
                    JcaCertStore store = new JcaCertStore(certs);
                    generator.addCertificates(store);
                    DigestCalculatorProvider digestProvider = new JcaDigestCalculatorProviderBuilder()
                            .build();
                    SignerInfoGeneratorBuilder infoGenBuilder = new SignerInfoGeneratorBuilder(
                            digestProvider);
                    X509CertificateHolder certHolder = new X509CertificateHolder(
                            ca.getRecipient().getEncoded());
                    ContentSigner contentSigner = new JcaContentSignerBuilder(
                            "SHA1withRSA").build(ca.getRecipientKey());
                    SignerInfoGenerator infoGen = infoGenBuilder.build(contentSigner,
                            certHolder);
                    generator.addSignerInfoGenerator(infoGen);

                    CMSSignedData degenerateSd = generator
                            .generate(new CMSAbsentContent());
                    byte[] bytes = degenerateSd.getEncoded();
                    res.setBody(bytes);
                }
            } catch (CertificateEncodingException e) {
                error(e);
            } catch (CMSException e) {
                error(e);
            } catch (OperatorCreationException e) {
                error(e);
            } catch (IOException e) {
                error(e);
            }
        }

        @Override
        public void foundCertificate(List<X509Certificate> issued) {
            try {
                if (issued == null || issued.size() == 0) {
                    encodeCertRep(new CertRep(transId, senderNonce,
                            recipientNonce, FailInfo.badCertId));
                } else {
                    CMSSignedData messageData = getMessageData(issued);
                    encodeCertRep(new CertRep(transId, senderNonce,
                            recipientNonce, messageData));
                }
            } catch (CertificateEncodingException e) {
                error(e);
            } catch (CMSException e) {
                error(e);
            }
        }

        @Override
        public void issuedCertificate(List<X509Certificate> issued) {
            try {
                if (issued == null || issued.size() == 0) {
                    encodeCertRep(new CertRep(transId, senderNonce,
                            recipientNonce));
                } else {
                    CMSSignedData messageData = getMessageData(issued);
                    encodeCertRep(new CertRep(transId, senderNonce,
                            recipientNonce, messageData));
                }
            } catch (CertificateEncodingException e) {
                error(e);
            } catch (CMSException e) {
                error(e);
            }
        }

        private CMSSignedData getMessageData(List<X509Certificate> certs)
                throws CertificateEncodingException, CMSException {
            CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
            JcaCertStore store = new JcaCertStore(certs);
            generator.addCertificates(store);
            return generator.generate(new CMSAbsentContent());
        }

        @Override
        public void crl(X509CRL crl) {
            try {
                CMSSignedData messageData = getMessageData(crl);
                encodeCertRep(new CertRep(transId, senderNonce, recipientNonce,
                        messageData));
            } catch (CRLException e) {
                error(e);
            } catch (CMSException e) {
                error(e);
            }
        }

        private CMSSignedData getMessageData(final X509CRL crl)
                throws CRLException, CMSException {
            CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
            JcaCRLStore store;
            if (crl == null) {
                store = new JcaCRLStore(Collections.emptyList());
            } else {
                store = new JcaCRLStore(Collections.singleton(crl));
            }
            generator.addCertificates(store);
            return generator.generate(new CMSAbsentContent());
        }

        @Override
        public void error(Throwable e) {
            LOGGER.error("Error while processing request", e);
            if (e instanceof OperationFailureException) {
                OperationFailureException ofe = (OperationFailureException) e;
                encodeCertRep(new CertRep(transId, senderNonce, recipientNonce,
                        ofe.getFailInfo()));
            } else {
                res.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
                res.setMessage("Failed to process request");
            }
        }

        private void encodeCertRep(CertRep certRep) {
            try {
                PkcsPkiEnvelopeEncoder envEncoder = new PkcsPkiEnvelopeEncoder(
                        reqCert, "DESede");
                PkiMessageEncoder encoder = new PkiMessageEncoder(ca.getSignerKey(),
                        ca.getSigner(), ca.getSignerCertificateChain(), envEncoder);
                CMSSignedData signedData = encoder.encode(certRep);
                res.setHeader("Content-Type", "application/x-pki-message");
                res.setBody(signedData.getEncoded());
            } catch (MessageEncodingException e) {
                throw new RuntimeException(e);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }

        @Override
        public void badRequest(String message) {
            LOGGER.error(message);
            res.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            res.setMessage(message);
        }

        @Override
        public void badRequest(String message, Throwable cause) {
            LOGGER.error(message, cause);
            res.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            res.setMessage(message);
        }

        void methodNotAllowed(
                String method, Operation operation,
                String... allowedMethods
        ) {
            LOGGER.error(
                    "Method {} not allowed for operation {}",
                    method, operation
            );
            res.setStatus(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
            StringBuilder b = new StringBuilder();
            for (String m : allowedMethods) {
                if (b.length() > 0) {
                    b.append(", ");
                }
                b.append(m);
            }
            res.setHeader("Allow", b.toString());
        }

        void setSenderNonce(Nonce senderNonce) {
            this.senderNonce = senderNonce;
        }

        void setRecipientNonce(Nonce recipientNonce) {
            this.recipientNonce = recipientNonce;
        }

        void setTransactionId(TransactionId transactionId) {
            this.transId = transactionId;
        }

        void setRequestCertificate(X509Certificate reqCert) {
            this.reqCert = reqCert;
        }
    }
}
