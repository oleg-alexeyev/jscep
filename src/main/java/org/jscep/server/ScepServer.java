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
import java.security.GeneralSecurityException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import javax.servlet.ServletException;
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
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Base64;
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
 * This class provides a base Servlet which can be extended using the abstract
 * methods to implement a SCEP CA (or RA).
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

    public final void service(final ScepRequest req, final ScepResponse res)
            throws Exception {
        byte[] body = getMessageBytes(req);

        final Operation op;
        try {
            op = getOperation(req);
            if (op == null) {
                // The operation parameter must be set.

                res.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                res.setMessage("Missing \"operation\" parameter.");

                return;
            }
        } catch (IllegalArgumentException e) {
            // The operation was not recognised.

            res.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            res.setMessage("Invalid \"operation\" parameter.");

            return;
        }

        LOGGER.debug("Incoming Operation: " + op);

        final String reqMethod = req.getMethod();

        if (op == Operation.PKI_OPERATION) {
            if (!reqMethod.equals(POST) && !reqMethod.equals(GET)) {
                // PKIOperation must be sent using GET or POST

                res.setStatus(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
                res.setHeader("Allow", GET + ", " + POST);

                return;
            }
        } else {
            if (!reqMethod.equals(GET)) {
                // Operations other than PKIOperation must be sent using GET

                res.setStatus(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
                res.setHeader("Allow", GET);

                return;
            }
        }

        LOGGER.debug("Method " + reqMethod + " Allowed for Operation: " + op);

        if (op == Operation.GET_CA_CAPS) {
            LOGGER.debug("Invoking doGetCaCaps");
            doGetCaCaps(req, res);
        } else if (op == Operation.GET_CA_CERT) {
            LOGGER.debug("Invoking doGetCaCert");
            doGetCaCert(req, res);
        } else if (op == Operation.GET_NEXT_CA_CERT) {
            LOGGER.debug("Invoking doGetNextCaCert");
            doGetNextCaCert(req, res);
        } else if (op == Operation.PKI_OPERATION) {
            // PKIOperation

            res.setHeader("Content-Type", "application/x-pki-message");

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
                throw new ServletException(e);
            }

            PkiMessage<?> msg;
            try {
                PkcsPkiEnvelopeDecoder envDecoder = new PkcsPkiEnvelopeDecoder(
                        ca.getRecipient(), ca.getRecipientKey());
                PkiMessageDecoder decoder = new PkiMessageDecoder(reqCert,
                        envDecoder);
                msg = decoder.decode(sd);
            } catch (MessageDecodingException e) {
                LOGGER.error("Error decoding request", e);
                throw new ServletException(e);
            }

            LOGGER.debug("Processing message {}", msg);

            MessageType msgType = msg.getMessageType();
            Object msgData = msg.getMessageData();

            Nonce senderNonce = Nonce.nextNonce();
            TransactionId transId = msg.getTransactionId();
            Nonce recipientNonce = msg.getSenderNonce();
            CertRep certRep;

            if (msgType == MessageType.GET_CERT) {
                final IssuerAndSerialNumber iasn = (IssuerAndSerialNumber) msgData;
                final X500Name principal = iasn.getName();
                final BigInteger serial = iasn.getSerialNumber().getValue();

                try {
                    List<X509Certificate> issued = ca.getCert(principal, serial);
                    if (issued.size() == 0) {
                        certRep = new CertRep(transId, senderNonce,
                                recipientNonce, FailInfo.badCertId);
                    } else {
                        CMSSignedData messageData = getMessageData(issued);

                        certRep = new CertRep(transId, senderNonce,
                                recipientNonce, messageData);
                    }
                } catch (OperationFailureException e) {
                    certRep = new CertRep(transId, senderNonce, recipientNonce,
                            e.getFailInfo());
                }
            } else if (msgType == MessageType.GET_CERT_INITIAL) {
                final IssuerAndSubject ias = (IssuerAndSubject) msgData;
                final X500Name issuer = X500Name.getInstance(ias.getIssuer());
                final X500Name subject = X500Name.getInstance(ias.getSubject());

                try {
                    List<X509Certificate> issued = ca.getCertInitial(issuer, subject, transId);

                    if (issued.size() == 0) {
                        certRep = new CertRep(transId, senderNonce,
                                recipientNonce);
                    } else {
                        CMSSignedData messageData = getMessageData(issued);

                        certRep = new CertRep(transId, senderNonce,
                                recipientNonce, messageData);
                    }
                } catch (OperationFailureException e) {
                    certRep = new CertRep(transId, senderNonce, recipientNonce,
                            e.getFailInfo());
                }
            } else if (msgType == MessageType.GET_CRL) {
                final IssuerAndSerialNumber iasn = (IssuerAndSerialNumber) msgData;
                final X500Name issuer = iasn.getName();
                final BigInteger serialNumber = iasn.getSerialNumber()
                        .getValue();

                try {
                    LOGGER.debug("Invoking doGetCrl");
                    CMSSignedData messageData = getMessageData(ca.getCrl(issuer, serialNumber));

                    certRep = new CertRep(transId, senderNonce, recipientNonce,
                            messageData);
                } catch (OperationFailureException e) {
                    LOGGER.error("Error executing GetCRL request", e);
                    certRep = new CertRep(transId, senderNonce, recipientNonce,
                            e.getFailInfo());
                }
            } else if (msgType == MessageType.PKCS_REQ) {
                final PKCS10CertificationRequest certReq = (PKCS10CertificationRequest) msgData;

                try {
                    LOGGER.debug("Invoking doEnrol");
                    List<X509Certificate> issued = ca.enrol(certReq, reqCert, transId);

                    if (issued.size() == 0) {
                        certRep = new CertRep(transId, senderNonce,
                                recipientNonce);
                    } else {
                        CMSSignedData messageData = getMessageData(issued);

                        certRep = new CertRep(transId, senderNonce,
                                recipientNonce, messageData);
                    }
                } catch (OperationFailureException e) {
                    certRep = new CertRep(transId, senderNonce, recipientNonce,
                            e.getFailInfo());
                }
            } else {
                throw new IllegalArgumentException(
                        "Unknown Message for Operation"
                );
            }

            PkcsPkiEnvelopeEncoder envEncoder = new PkcsPkiEnvelopeEncoder(
                    reqCert, "DESede");
            PkiMessageEncoder encoder = new PkiMessageEncoder(ca.getSignerKey(),
                    ca.getSigner(), ca.getSignerCertificateChain(), envEncoder);
            CMSSignedData signedData;
            try {
                signedData = encoder.encode(certRep);
            } catch (MessageEncodingException e) {
                LOGGER.error("Error decoding response", e);
                throw e;
            }

            res.setBody(signedData.getEncoded());
        } else {
            res.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            res.setMessage("Unknown Operation");
        }
    }

    private CMSSignedData getMessageData(final List<X509Certificate> certs)
            throws IOException, CMSException, GeneralSecurityException {
        CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
        JcaCertStore store;
        try {
            store = new JcaCertStore(certs);
        } catch (CertificateEncodingException e) {
            throw new IOException(e);
        }
        generator.addCertificates(store);
        return generator.generate(new CMSAbsentContent());
    }

    private CMSSignedData getMessageData(final X509CRL crl) throws IOException,
            CMSException, GeneralSecurityException {
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

    private void doGetNextCaCert(final ScepRequest req,
            final ScepResponse res) throws Exception {
        res.setHeader("Content-Type", "application/x-x509-next-ca-cert");

        List<X509Certificate> certs = ca.getNextCaCertificate(req
                .getParameter(MSG_PARAM));

        if (certs.size() == 0) {
            res.setStatus(HttpServletResponse.SC_NOT_IMPLEMENTED);
            res.setMessage("GetNextCACert Not Supported");
        } else {
            CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
            JcaCertStore store;
            try {
                store = new JcaCertStore(certs);
            } catch (CertificateEncodingException e) {
                throw new IOException(e);
            }
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
    }

    private void doGetCaCert(final ScepRequest req,
            final ScepResponse res) throws Exception {
        final List<X509Certificate> certs = ca.getCaCertificate(req
                .getParameter(MSG_PARAM));
        final byte[] bytes;
        if (certs.size() == 0) {
            res.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            res.setMessage("GetCaCert failed to obtain CA from store");
            bytes = new byte[0];
        } else if (certs.size() == 1) {
            res.setHeader("Content-Type", "application/x-x509-ca-cert");
            bytes = certs.get(0).getEncoded();
        } else {
            res.setHeader("Content-Type", "application/x-x509-ca-ra-cert");
            CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
            JcaCertStore store;
            try {
                store = new JcaCertStore(certs);
            } catch (CertificateEncodingException e) {
                throw new IOException(e);
            }
            generator.addCertificates(store);
            CMSSignedData degenerateSd = generator
                    .generate(new CMSAbsentContent());
            bytes = degenerateSd.getEncoded();
        }

        res.setBody(bytes);
    }

    private Operation getOperation(final ScepRequest req) {
        String op = req.getParameter(OP_PARAM);
        if (op == null) {
            return null;
        }
        return Operation.forName(req.getParameter(OP_PARAM));
    }

    private void doGetCaCaps(final ScepRequest req,
            final ScepResponse res) throws Exception {
        res.setHeader("Content-Type", "text/plain");
        final Set<Capability> caps = ca.getCapabilities(req.getParameter(MSG_PARAM));
        StringBuilder builder = new StringBuilder();
        for (Capability cap : caps) {
            builder.append(cap.toString());
            builder.append('\n');
        }
        res.setMessage(builder.toString());
    }

    private byte[] getMessageBytes(final ScepRequest req)
            throws IOException {
        if (req.getMethod().equals(POST)) {
            return req.getBody();
        } else {
            Operation op = getOperation(req);

            if (op == Operation.PKI_OPERATION) {
                String msg = req.getParameter(MSG_PARAM);
                if (msg.length() == 0) {
                    return new byte[0];
                }
                if (LOGGER.isDebugEnabled()) {
                    LOGGER.debug("Decoding {}", msg);
                }
                return Base64.decode(msg);
            } else {
                return new byte[0];
            }
        }
    }
}
