/*
 * Copyright (c) 2009-2012 David Grant
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
package org.jscep.client;

import static org.bouncycastle.asn1.x509.Extension.cRLDistributionPoints;
import static org.jscep.client.CaProperties.Builder.caProperties;

import java.io.IOException;
import java.math.BigInteger;
import java.net.URL;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Collection;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.x500.X500Principal;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.CertException;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.RuntimeOperatorException;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.jscep.asn1.IssuerAndSubject;
import org.jscep.client.inspect.CertStoreInspector;
import org.jscep.client.inspect.CertStoreInspectorFactory;
import org.jscep.client.inspect.DefaultCertStoreInspectorFactory;
import org.jscep.client.verification.CertificateVerifier;
import org.jscep.message.PkcsPkiEnvelopeDecoder;
import org.jscep.message.PkcsPkiEnvelopeEncoder;
import org.jscep.message.PkiMessageDecoder;
import org.jscep.message.PkiMessageEncoder;
import org.jscep.transaction.EnrollmentTransaction;
import org.jscep.transaction.MessageType;
import org.jscep.transaction.NonEnrollmentTransaction;
import org.jscep.transaction.OperationFailureException;
import org.jscep.transaction.Transaction;
import org.jscep.transaction.Transaction.State;
import org.jscep.transaction.TransactionException;
import org.jscep.transaction.TransactionId;
import org.jscep.transport.ErrorDelegatingHandler;
import org.jscep.transport.ErrorMappingHandler;
import org.jscep.transport.ResultHandler;
import org.jscep.transport.ScepTransport;
import org.jscep.transport.ScepTransportBridgeFactory;
import org.jscep.transport.ScepTransportFactory;
import org.jscep.transport.TransportException;
import org.jscep.transport.TransportFactory.Method;
import org.jscep.transport.UrlConnectionTransportFactory;
import org.jscep.transport.request.GetCaCapsRequest;
import org.jscep.transport.request.GetCaCertRequest;
import org.jscep.transport.request.GetNextCaCertRequest;
import org.jscep.transport.response.Capabilities;
import org.jscep.transport.response.GetCaCapsResponseHandler;
import org.jscep.transport.response.GetCaCertResponseHandler;
import org.jscep.transport.response.GetNextCaCertResponseHandler;
import org.jscep.util.X500Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The <tt>ScepClient</tt> class is used for interacting with a SCEP server.
 * It's a non-blocking version of the client, providing for implementation
 * over non-blocking HTTP clients like Vert.x or Spring WebFlux.
 * <p>
 * Typical usage might look like so:
 *
 * <pre>
 *     // Create the client
 *     URL url = new URL(&quot;http://jscep.org/scep/pkiclient.exe&quot;);
 *     MessageDigest digest = MessageDigest.getInstance(&quot;SHA-256&quot;);
 *     byte[] expected = Hex.decode(&quot;835f179febba96f32a47610a679de400&quot;.toCharArray());
 *     CertificateVerifier verifier = new MessageDigestCertificateVerifier(digest, expected);
 *     scepClient()
 *             .url(url)
 *             .certificateVerifier(verifier)
 *             .transportFactory(new SomeNonBlockingTransportFactory())
 *             .build();
 *
 *     // Invoke operations on the client.
 *     client.getCaCapabilities((caps, e) -> e != null ? handleError(e) : handleCaps(caps));
 * </pre>
 *
 * Each of the operations of this class is overloaded with a profile argument to
 * support SCEP servers with multiple (or mandatory) profile names.
 * <p>
 * To provide for non-blocking behavior, methods accept a
 * <code>ResultHandler</code> callback which receives a result or an error
 * instead of returning result / throwing an exception. This can be used in
 * conjunction with other non-blocking APIs, e.g. with
 * <code><a href="https://docs.oracle.com/javase/8/docs/api/java/util/concurrent/CompletableFuture.html">CompletableFuture</a></code>
 * from Java 8:
 * <pre>
 *     CompletableFuture&lt;Capacities> f = new CompletableFuture()
 *     client.getCaCapabilities((caps, e) -> e != null ? f.completeExceptionally(e) : f.complete(caps);
 * </pre>
 * or with
 * <code><a href="http://projectreactor.io/docs/core/release/api/reactor/core/publisher/Mono.html">Mono</a></code>
 * from Project Reactor:
 * <pre>
 *     Mono.create(sink -> client.getCaCapabilities((caps, e) -> e != null ? sink.error(e) : sink.success(caps)));
 * </pre>
 */
public final class ScepClient {

    private static final Logger LOGGER = LoggerFactory.getLogger(ScepClient.class);

    // A requester MUST have the following information locally configured:
    //
    // 1. The Certification Authority IP address or fully qualified domain name
    // 2. The Certification Authority HTTP CGI script path
    //
    // We use a URL for this.
    private final URL url;
    // A requester MUST have the following information locally configured:
    //
    // 3. The identifying information that is used for authentication of the
    // Certification Authority in Section 4.1.1. This information MAY be
    // obtained from the user, or presented to the end user for manual
    // authorization during the protocol exchange (e.g. the user indicates
    // acceptance of a fingerprint via a user-interface element).
    //
    // We use a callback handler for this.
    private final CallbackHandler callbackHandler;
    private final CertStoreInspectorFactory inspectorFactory;
    private final ScepTransportFactory transportFactory;

    private ScepClient(Builder builder) {
        this.url = builder.url;
        this.callbackHandler = builder.callbackHandler;
        this.inspectorFactory = builder.inspectorFactory != null ?
                builder.inspectorFactory :
                new DefaultCertStoreInspectorFactory();
        this.transportFactory = builder.transportFactory != null ?
                builder.transportFactory :
                new ScepTransportBridgeFactory(new UrlConnectionTransportFactory());

        validateInput();
    }

    /**
     * Validates all the input to this client.
     */
    private void validateInput() {
        // Check for null values first.
        if (url == null) {
            throw new NullPointerException("URL should not be null");
        }
        if (!url.getProtocol().matches("^https?$")) {
            throw new IllegalArgumentException(
                    "URL protocol should be HTTP or HTTPS");
        }
        if (url.getRef() != null) {
            throw new IllegalArgumentException(
                    "URL should contain no reference");
        }
        if (url.getQuery() != null) {
            throw new IllegalArgumentException(
                    "URL should contain no query string");
        }
        if (callbackHandler == null) {
            throw new NullPointerException(
                    "Callback handler should not be null");
        }
    }

    // INFORMATIONAL REQUESTS

    /**
     * Retrieves the capabilities of the SCEP server.
     *
     * @param handler the handler accepting the result or
     *                empty {@link Capabilities} if a transport error occurs.
     */
    public void getCaCapabilities(final ResultHandler<Capabilities> handler) {
        // NON-TRANSACTIONAL
        getCaCapabilities(null, handler);
    }

    /**
     * Retrieves the capabilities of the SCEP server.
     * <p>
     * This method provides support for SCEP servers with multiple profiles.
     *
     * @param profile
     *            the SCEP server profile.
     * @param handler the handler accepting the result or
     *                empty {@link Capabilities} if a transport error occurs.
     */
    public void getCaCapabilities(final String profile,
                                  final ResultHandler<Capabilities> handler) {
        LOGGER.debug("Determining capabilities of SCEP server");
        // NON-TRANSACTIONAL
        GetCaCapsRequest req = new GetCaCapsRequest(profile);
        ScepTransport trans = transportFactory.forMethod(Method.GET, url);
        trans.sendRequest(req, new GetCaCapsResponseHandler(), new ResultHandler<Capabilities>() {
            @Override
            public void handle(Capabilities capabilities, Throwable e) {
                if (e instanceof TransportException) {
                    LOGGER.warn("AbstractTransport problem when determining capabilities. Using empty capabilities.");
                    handler.handle(new Capabilities(), null);
                } else {
                    handler.handle(capabilities, e);
                }
            }
        });
    }

    /**
     * Retrieves the certificates used by the SCEP server.
     * <p>
     * This method queries the server for the certificates it will use in a SCEP
     * message exchange. If the SCEP server represents a single entity, only a
     * single CA certificate will be returned. If the SCEP server supports
     * multiple entities (for example, if it uses a separate entity for signing
     * SCEP messages), additional RA certificates will also be returned.
     *
     * @param handler the handler accepting a {@link CertStore} containing
     *                all CA/RA certificates or {@link ClientException} if an
     *                error occurs.
     * @see DefaultCertStoreInspectorFactory
     */
    public void getCaCertificate(ResultHandler<CertStore> handler) {
        getCaCertificate(null, handler);
    }

    /**
     * Retrieves the certificates used by the SCEP server.
     * <p>
     * This method queries the server for the certificates it will use in a SCEP
     * message exchange. If the SCEP server represents a single entity, only a
     * single CA certificate will be returned. If the SCEP server supports
     * multiple entities (for example, if it uses a separate entity for signing
     * SCEP messages), additional RA certificates will also be returned.
     * <p>
     * This method provides support for SCEP servers with multiple profiles.
     *
     * @param profile
     *            the SCEP server profile.
     * @param handler the handler accepting a {@link CertStore} containing
     *                all CA/RA certificates or {@link ClientException} if an
     *                error occurs.
     * @see CertStoreInspector
     */
    public void getCaCertificate(final String profile,
                                 final ResultHandler<CertStore> handler) {
        LOGGER.debug("Retrieving current CA certificate");
        // NON-TRANSACTIONAL
        // CA and RA public key distribution
        GetCaCertRequest req = new GetCaCertRequest(profile);
        ScepTransport trans = transportFactory.forMethod(Method.GET, url);
        trans.sendRequest(req, new GetCaCertResponseHandler(),
                new ClientErrorMappingHandler<CertStore>(new ErrorDelegatingHandler<CertStore>(handler) {
                    @Override
                    protected void doHandle(CertStore store) {
                        CertStoreInspector certs = inspectorFactory.getInstance(store);
                        X509Certificate issuer = certs.getIssuer();
                        if (verifyCA(issuer, handler)
                                && verifyRA(issuer, certs.getRecipient(), handler)
                                && verifyRA(issuer, certs.getSigner(), handler)) {
                            handler.handle(store, null);
                        }
                    }
                })
        );
    }

    private boolean verifyCA(
            final X509Certificate cert,
            final ResultHandler<?> handler
    ) {
        CertificateVerificationCallback callback
                = new CertificateVerificationCallback(cert);
        try {
            LOGGER.debug("Requesting certificate verification.");
            Callback[] callbacks = new Callback[1];
            callbacks[0] = callback;
            callbackHandler.handle(callbacks);
        } catch (UnsupportedCallbackException e) {
            LOGGER.debug("Certificate verification failed.");
            handler.handle(null, new ClientException(e));
            return false;
        } catch (IOException e) {
            handler.handle(null, new ClientException(e));
            return false;
        }

        if (!callback.isVerified()) {
            LOGGER.debug("Certificate verification failed.");
            handler.handle(null,
                    new ClientException("CA certificate verification failed."));
            return false;
        } else {
            LOGGER.debug("Certificate verification passed.");
            return true;
        }
    }

    private boolean verifyRA(
            final X509Certificate ca, final X509Certificate ra,
            final ResultHandler<?> handler
    ) {
        LOGGER.debug("Verifying signature of RA certificate");
        if (ca.equals(ra)) {
            LOGGER.debug("RA and CA are identical");
            return true;
        }
        try {
            JcaX509CertificateHolder raHolder = new JcaX509CertificateHolder(ra);
            ContentVerifierProvider verifierProvider = new JcaContentVerifierProviderBuilder()
                    .build(ca);
            if (!raHolder.isSignatureValid(verifierProvider)) {
                LOGGER.debug("Signature verification failed for RA.");
                handler.handle(null,
                        new ClientException("RA not issued by CA"));
                return false;
            } else {
                LOGGER.debug("Signature verification passed for RA.");
                return true;
            }
        } catch (CertException e) {
            handler.handle(null, new ClientException(e));
            return false;
        } catch (CertificateEncodingException e) {
            handler.handle(null, new ClientException(e));
            return false;
        } catch (OperatorCreationException e) {
            handler.handle(null, new ClientException(e));
            return false;
        }
    }

    /**
     * Retrieves the next certificate to be used by the CA.
     * <p>
     * This method will query the SCEP server to determine if the CA is
     * scheduled to start using a new certificate for issuing.
     *
     * @param handler the handler accepting a {@link CertStore} containing
     *                all CA/RA certificates or {@link ClientException} if an
     *                error occurs.
     * @see CertStoreInspector
     */
    public void getRolloverCertificate(ResultHandler<CertStore> handler) {
        getRolloverCertificate(null, handler);
    }

    /**
     * Retrieves the next certificate to be used by the CA.
     * <p>
     * This method will query the SCEP server to determine if the CA is
     * scheduled to start using a new certificate for issuing.
     * <p>
     * This method provides support for SCEP servers with multiple profiles.
     *
     * @param profile
     *            the SCEP server profile.
     * @param handler the handler accepting a {@link CertStore} containing
     *                all CA/RA certificates or {@link ClientException} if an
     *                error occurs.
     * @see CertStoreInspector
     */
    public void getRolloverCertificate(
            final String profile,
            final ResultHandler<CertStore> handler
    ) {
        LOGGER.debug("Retrieving next CA certificate from CA");
        // NON-TRANSACTIONAL
        caProperties(this)
                .profile(profile)
                .requestCaps()
                .requestCaCertStore()
                .whenReady(new ClientErrorMappingHandler<CaProperties>(
                        new ErrorDelegatingHandler<CaProperties>(handler) {
                            @Override
                            protected void doHandle(CaProperties caProperties) {
                                getNextCaCert(profile, caProperties, handler);
                            }
                        }
                ));
    }

    private void getNextCaCert(
            String profile, CaProperties caProperties,
            ResultHandler<CertStore> handler
    ) {
        if (!caProperties.getCaCaps().isRolloverSupported()) {
            handler.handle(null, new UnsupportedOperationException());
        } else {
            // The CA or RA
            CertStoreInspector certs = inspectorFactory.getInstance
                    (caProperties.getCaCertStore());
            final X509Certificate signer = certs.getSigner();
            final ScepTransport trans = transportFactory
                    .forMethod(Method.GET, url);
            final GetNextCaCertRequest req = new GetNextCaCertRequest(profile);
            trans.sendRequest(
                    req, new GetNextCaCertResponseHandler(signer), handler
            );
        }
    }

    // TRANSACTIONAL

    /**
     * Returns the certificate revocation list a given issuer and serial number.
     * <p>
     * This method requests a CRL for a certificate as identified by the issuer
     * name and the certificate serial number.
     *
     * @param identity
     *            the identity of the client.
     * @param key
     *            the private key to sign the SCEP request.
     * @param issuer
     *            the name of the certificate issuer.
     * @param serial
     *            the serial number of the certificate.
     * @param handler the handler accepting a {@link X509CRL},
     *               or {@link OperationFailureException} if the request fails,
     *               or {@link ClientException} if an error occurs.
     */
    public void getRevocationList(final X509Certificate identity,
            final PrivateKey key, final X500Principal issuer,
            final BigInteger serial, final ResultHandler<X509CRL> handler) {
        getRevocationList(identity, key, issuer, serial, null, handler);
    }

    /**
     * Returns the certificate revocation list a given issuer and serial number.
     * <p>
     * This method requests a CRL for a certificate as identified by the issuer
     * name and the certificate serial number.
     * <p>
     * This method provides support for SCEP servers with multiple profiles.
     *
     * @param identity
     *            the identity of the client.
     * @param key
     *            the private key to sign the SCEP request.
     * @param issuer
     *            the name of the certificate issuer.
     * @param serial
     *            the serial number of the certificate.
     * @param profile
     *            the SCEP server profile.
     * @param handler the handler accepting a {@link X509CRL},
     *               or {@link OperationFailureException} if the request fails,
     *               or {@link ClientException} if an error occurs.
     */
    public void getRevocationList(
            final X509Certificate identity,
            final PrivateKey key, final X500Principal issuer,
            final BigInteger serial, final String profile,
            final ResultHandler<X509CRL> handler
    ) {
        LOGGER.debug("Retrieving CRL from CA");
        caProperties(this)
                .profile(profile)
                .requestCaps()
                .requestCaCertStore()
                .whenReady(new ClientErrorMappingHandler<CaProperties>(
                        new ErrorDelegatingHandler<CaProperties>(handler) {
                            @Override
                            protected void doHandle(CaProperties caProperties) {
                                doGetCrl(identity, key, issuer, serial,
                                        caProperties, handler);
                            }
                        }
                ));
    }

    @SuppressWarnings("unchecked")
    private void doGetCrl(
            final X509Certificate identity,
            final PrivateKey key, final X500Principal issuer,
            final BigInteger serial, final CaProperties caProperties,
            final ResultHandler<X509CRL> handler
    ) {
        // TRANSACTIONAL
        // CRL query
        checkDistributionPoints(caProperties.getCaCertStore());

        X500Name name = new X500Name(issuer.getName());
        IssuerAndSerialNumber iasn = new IssuerAndSerialNumber(name, serial);
        ScepTransport transport = createTransport(caProperties.getCaCaps());
        final Transaction t = new NonEnrollmentTransaction(
                transport,
                getEncoder(identity, key, caProperties),
                getDecoder(identity, key, caProperties),
                iasn, MessageType.GET_CRL
        );

        t.send(new ClientErrorMappingHandler<State>(
                new ErrorDelegatingHandler<State>(handler) {
                    @Override
                    protected void doHandle(State state) {
                        if (state == State.CERT_ISSUED) {
                            try {
                                Collection<X509CRL> crls = (Collection<X509CRL>) t
                                        .getCertStore().getCRLs(null);
                                if (crls.size() == 0) {
                                    handler.handle(null, null);
                                } else {
                                    handler.handle(crls.iterator().next(), null);
                                }
                            } catch (CertStoreException e) {
                                handler.handle(null, e);
                            }
                        } else if (state == State.CERT_REQ_PENDING) {
                            handler.handle(null, new IllegalStateException());
                        } else {
                            handler.handle(null,
                                    new OperationFailureException(
                                            t.getFailInfo()));
                        }
                    }
                }
        ));
    }

    private void checkDistributionPoints(final CertStore caCertStore) {
        CertStoreInspector certs = inspectorFactory.getInstance(caCertStore);
        final X509Certificate ca = certs.getIssuer();
        if (ca.getExtensionValue(cRLDistributionPoints.getId()) != null) {
            LOGGER.warn("CA supports distribution points");
        }
    }

    /**
     * Retrieves the certificate corresponding to the provided serial number.
     * <p>
     * This request relates only to the current CA certificate. If the CA
     * certificate has changed since the requested certificate was issued, this
     * operation will fail.
     *
     * @param identity
     *            the identity of the client.
     * @param key
     *            the private key to sign the SCEP request.
     * @param serial
     *            the serial number of the requested certificate.
     * @param handler the handler accepting an {@link X509Certificate},
     *               or {@link OperationFailureException} if the request fails,
     *               or {@link ClientException} if an error occurs.
     */
    public void getCertificate(
            final X509Certificate identity,
            final PrivateKey key, final BigInteger serial,
            final ResultHandler<CertStore> handler
    ) {
        getCertificate(identity, key, serial, null, handler);
    }

    /**
     * Retrieves the certificate corresponding to the provided serial number.
     * <p>
     * This request relates only to the current CA certificate. If the CA
     * certificate has changed since the requested certificate was issued, this
     * operation will fail.
     * <p>
     * This method provides support for SCEP servers with multiple profiles.
     *
     * @param identity
     *            the identity of the client.
     * @param key
     *            the private key to sign the SCEP request.
     * @param serial
     *            the serial number of the requested certificate.
     * @param profile
     *            the SCEP server profile.
     * @param handler the handler accepting an {@link X509Certificate},
     *               or {@link OperationFailureException} if the request fails,
     *               or {@link ClientException} if an error occurs.
     */
    public void getCertificate(
            final X509Certificate identity,
            final PrivateKey key, final BigInteger serial, final String profile,
            final ResultHandler<CertStore> handler
    ) {
        LOGGER.debug("Retrieving certificate from CA");
        // TRANSACTIONAL
        // Certificate query
        caProperties(this)
                .profile(profile)
                .requestCaps()
                .requestCaCertStore()
                .whenReady(new ClientErrorMappingHandler<CaProperties>(
                        new ErrorDelegatingHandler<CaProperties>(handler) {
                            @Override
                            protected void doHandle(CaProperties caProperties) {
                                doGetCertificate(identity, key, serial,
                                        caProperties, handler);
                            }
                        }
                ));
    }

    private void doGetCertificate(
            final X509Certificate identity,
            final PrivateKey key, final BigInteger serial,
            final CaProperties caProperties,
            final ResultHandler<CertStore> handler
    ) {
        final CertStore store = caProperties.getCaCertStore();
        CertStoreInspector certs = inspectorFactory.getInstance(store);
        final X509Certificate ca = certs.getIssuer();

        X500Name name = new X500Name(ca.getSubjectX500Principal().toString());
        IssuerAndSerialNumber iasn = new IssuerAndSerialNumber(name, serial);
        ScepTransport transport = createTransport(caProperties.getCaCaps());
        final Transaction t = new NonEnrollmentTransaction(transport,
                getEncoder(identity, key, caProperties),
                getDecoder(identity, key, caProperties),
                iasn, MessageType.GET_CERT);

        t.send(new ClientErrorMappingHandler<State>(
                new ErrorDelegatingHandler<State>(handler) {
                    @Override
                    protected void doHandle(State state) {
                        if (state == State.CERT_ISSUED) {
                            handler.handle(t.getCertStore(), null);
                        } else if (state == State.CERT_REQ_PENDING) {
                            handler.handle(null, new IllegalStateException());
                        } else {
                            handler.handle(null,
                                    new OperationFailureException(
                                            t.getFailInfo()));
                        }
                    }
                }
        ));
    }

    /**
     * Sends a CSR to the SCEP server for enrolling in a PKI.
     * <p>
     * This method enrols the provider <tt>CertificationRequest</tt> into the
     * PKI represented by the SCEP server.
     *
     * @param identity
     *            the identity of the client.
     * @param key
     *            the private key to sign the SCEP request.
     * @param csr
     *            the CSR to enrol.
     * @param handler the handler accepting an {@link EnrollmentResponse},
     *               or {@link TransactionException} if there is a problem
     *               with the SCEP transaction, or {@link ClientException}
     *               if an error occurs.
     * @see CertStoreInspector
     */
    public void enrol(
            final X509Certificate identity,
            final PrivateKey key, final PKCS10CertificationRequest csr,
            final ResultHandler<EnrollmentResponse> handler
    ) throws ClientException {
        enrol(identity, key, csr, null, handler);
    }

    /**
     * Sends a CSR to the SCEP server for enrolling in a PKI.
     * <p>
     * This method enrols the provided <tt>CertificationRequest</tt> into the
     * PKI represented by the SCEP server.
     *
     * @param identity
     *            the identity of the client.
     * @param key
     *            the private key to sign the SCEP request.
     * @param csr
     *            the CSR to enrol.
     * @param profile
     *            the SCEP server profile.
     * @param handler the handler accepting an {@link EnrollmentResponse},
     *               or {@link TransactionException} if there is a problem
     *               with the SCEP transaction, or {@link ClientException}
     *               if an error occurs.
     * @see CertStoreInspector
     */
    public void enrol(
            final X509Certificate identity,
            final PrivateKey key,
            final PKCS10CertificationRequest csr,
            final String profile,
            final ResultHandler<EnrollmentResponse> handler
    ) {

        caProperties(this)
                .profile(profile)
                .requestCaps()
                .requestCaCertStore()
                .whenReady(new ClientErrorMappingHandler<CaProperties>(
                        new ErrorDelegatingHandler<CaProperties>(handler) {
                            @Override
                            protected void doHandle(CaProperties caProperties) {
                                doEnrol(identity, key, csr,
                                        caProperties, handler);
                            }
                        }
                ));
    }

    private void doEnrol(
            final X509Certificate identity,
            final PrivateKey key,
            final PKCS10CertificationRequest csr,
            final CaProperties caProperties,
            final ResultHandler<EnrollmentResponse> handler
    ) {
        LOGGER.debug("Enrolling certificate with CA");

        boolean selfSigned;
        try {
            selfSigned = isSelfSigned(identity);
        } catch (ClientException e) {
            handler.handle(null, e);
            return;
        }

        if (selfSigned) {
            LOGGER.debug("Certificate is self-signed");
            X500Name csrSubject = csr.getSubject();
            X500Name idSubject = X500Utils.toX500Name(identity
                    .getSubjectX500Principal());

            if (!csrSubject.equals(idSubject)) {
                LOGGER.error("The self-signed certificate MUST use the same subject name as in the PKCS#10 request.");
            }
        }

        // TRANSACTIONAL
        // Certificate enrollment
        final ScepTransport transport = createTransport
                (caProperties.getCaCaps());
        PkiMessageEncoder encoder = getEncoder(identity, key, caProperties);
        PkiMessageDecoder decoder = getDecoder(identity, key, caProperties);
        final EnrollmentTransaction trans;
        try {
            trans = new EnrollmentTransaction(transport, encoder, decoder, csr);
        } catch (TransactionException e) {
            handler.handle(null, e);
            return;
        }

        try {
            MessageDigest digest = caProperties.getCaCaps()
                    .getStrongestMessageDigest();
            byte[] hash = digest.digest(csr.getEncoded());

            LOGGER.debug("{} PKCS#10 Fingerprint: [{}]", digest.getAlgorithm(),
                    new String(Hex.encodeHex(hash)));
        } catch (IOException e) {
            LOGGER.error("Error getting encoded CSR", e);
        }

        send(trans, handler);
    }

    private boolean isSelfSigned(final X509Certificate cert)
            throws ClientException {
        try {
            JcaX509CertificateHolder holder = new JcaX509CertificateHolder(cert);
            ContentVerifierProvider verifierProvider = new JcaContentVerifierProviderBuilder()
                    .build(holder);

            return holder.isSignatureValid(verifierProvider);
        } catch (RuntimeOperatorException e) {
            if(e.getCause() instanceof  SignatureException) {
                LOGGER.warn("SignatureException detected so we consider that the certificate is not self signed");
                return false;
            }
            throw new ClientException(e);
        } catch (Exception e) {
            throw new ClientException(e);
        }
    }

    public void poll(
            final X509Certificate identity,
            final PrivateKey identityKey, final X500Principal subject,
            final TransactionId transId,
            final ResultHandler<EnrollmentResponse> handler
    ) {
        poll(identity, identityKey, subject, transId, null, handler);
    }

    /**
     * Polls the SCEP server for enrollment results.
     *
     * @param identity
     *            the identity of the client.
     * @param identityKey
     *            the private key to sign the SCEP request.
     * @param subject
     *            subject of the original certificate request.
     * @param transId
     *            id of the original enrollment transaction.
     * @param profile
     *            the SCEP server profile.
     * @param handler the handler accepting an {@link EnrollmentResponse},
     *               or {@link TransactionException} if there is a problem
     *               with the SCEP transaction, or {@link ClientException}
     *               if an error occurs.
     * @see CertStoreInspector
     */
    public void poll(
            final X509Certificate identity,
            final PrivateKey identityKey, final X500Principal subject,
            final TransactionId transId, final String profile,
            final ResultHandler<EnrollmentResponse> handler
    ) {
        caProperties(this)
                .profile(profile)
                .requestCaps()
                .requestCaCertStore()
                .whenReady(new ClientErrorMappingHandler<CaProperties>(
                        new ErrorDelegatingHandler<CaProperties>(handler) {
                            @Override
                            protected void doHandle(CaProperties caProperties) {
                                doPoll(identity, identityKey, subject,
                                        transId, caProperties, handler);
                            }
                        }
                ));
    }

    private void doPoll(
            final X509Certificate identity,
            final PrivateKey identityKey,
            final X500Principal subject,
            final TransactionId transId,
            final CaProperties caProperties,
            final ResultHandler<EnrollmentResponse> handler
    ) {
        final ScepTransport transport = createTransport(caProperties.getCaCaps());
        CertStore store = caProperties.getCaCertStore();
        CertStoreInspector certStore = inspectorFactory.getInstance(store);
        X509Certificate issuer = certStore.getIssuer();

        PkiMessageEncoder encoder = getEncoder(identity, identityKey, caProperties);
        PkiMessageDecoder decoder = getDecoder(identity, identityKey, caProperties);

        IssuerAndSubject ias = new IssuerAndSubject(X500Utils.toX500Name(issuer
                .getSubjectX500Principal()), X500Utils.toX500Name(subject));

        final EnrollmentTransaction trans = new EnrollmentTransaction(
                transport, encoder, decoder, ias, transId);
        send(trans, handler);
    }

    private void send(
            final EnrollmentTransaction trans,
            final ResultHandler<EnrollmentResponse> handler
    ) {
        trans.send(
                new ErrorDelegatingHandler<State>(handler) {
                    @Override
                    protected void doHandle(State s) {
                        handleTransactionState(trans, s, handler);
                    }
                }
        );
    }

    private void handleTransactionState(
            final EnrollmentTransaction trans,
            final State s,
            final ResultHandler<EnrollmentResponse> handler
    ) {
        if (s == State.CERT_ISSUED) {
            handler.handle(
                    new EnrollmentResponse(trans.getId(), trans.getCertStore()),
                    null
            );
        } else if (s == State.CERT_REQ_PENDING) {
            handler.handle(
                    new EnrollmentResponse(trans.getId()),
                    null
            );
        } else {
            handler.handle(
                    new EnrollmentResponse(trans.getId(), trans.getFailInfo()),
                    null
            );
        }
    }

    private PkiMessageEncoder getEncoder(final X509Certificate identity,
            final PrivateKey priKey, final CaProperties caProperties
    ) {
        CertStore store = caProperties.getCaCertStore();
        Capabilities caps = caProperties.getCaCaps();
        CertStoreInspector certs = inspectorFactory.getInstance(store);
        X509Certificate recipientCertificate = certs.getRecipient();
        PkcsPkiEnvelopeEncoder envEncoder = new PkcsPkiEnvelopeEncoder(
                recipientCertificate, caps.getStrongestCipher());

        String sigAlg = caps.getStrongestSignatureAlgorithm();
        return new PkiMessageEncoder(priKey, identity, envEncoder, sigAlg);
    }

    private PkiMessageDecoder getDecoder(final X509Certificate identity,
            final PrivateKey key, final CaProperties caProperties
    ) {
        final CertStore store = caProperties.getCaCertStore();
        CertStoreInspector certs = inspectorFactory.getInstance(store);
        X509Certificate signer = certs.getSigner();
        PkcsPkiEnvelopeDecoder envDecoder = new PkcsPkiEnvelopeDecoder(
                identity, key);

        return new PkiMessageDecoder(signer, envDecoder);
    }

    /**
     * Creates a new transport based on the capabilities of the server.
     */
    private ScepTransport createTransport(final Capabilities caps) {
        if (caps.isPostSupported()) {
            return transportFactory.forMethod(Method.POST, url);
        } else {
            return transportFactory.forMethod(Method.GET, url);
        }
    }

    public static final class Builder {

        public static Builder scepClient() {
            return new Builder();
        }

        private URL url;
        private CallbackHandler callbackHandler;
        private CertStoreInspectorFactory inspectorFactory;
        private ScepTransportFactory transportFactory;

        public Builder url(URL url) {
            this.url = url;
            return this;
        }

        public Builder callbackHandler(CallbackHandler callbackHandler) {
            this.callbackHandler = callbackHandler;
            return this;
        }

        public Builder certificateVerifier(CertificateVerifier verifier) {
            this.callbackHandler = new DefaultCallbackHandler(verifier);
            return this;
        }

        public Builder certStoreInspectorFactory(
                CertStoreInspectorFactory inspectorFactory) {
            this.inspectorFactory = inspectorFactory;
            return this;
        }

        public Builder transportFactory(ScepTransportFactory transportFactory) {
        	this.transportFactory = transportFactory;
        	return this;
        }

        public ScepClient build() {
            return new ScepClient(this);
        }
    }

    private static final class ClientErrorMappingHandler<T>
            extends ErrorMappingHandler<T> {

        public ClientErrorMappingHandler(ResultHandler<T> responseHandler) {
            super(responseHandler);
        }

        @Override
        protected Throwable mapError(Throwable e) {
            if (e instanceof ClientException) {
                return e;
            }
            return new ClientException(e);
        }
    }
}
