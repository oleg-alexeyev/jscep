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

import static org.jscep.client.ScepClient.Builder.scepClient;

import java.math.BigInteger;
import java.net.URL;
import java.security.PrivateKey;
import java.security.cert.CertStore;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.jscep.client.inspect.CertStoreInspector;
import org.jscep.client.inspect.CertStoreInspectorFactory;
import org.jscep.client.inspect.DefaultCertStoreInspectorFactory;
import org.jscep.client.verification.CertificateVerifier;
import org.jscep.transaction.OperationFailureException;
import org.jscep.transaction.TransactionException;
import org.jscep.transaction.TransactionId;
import org.jscep.transport.ResultHolder;
import org.jscep.transport.ScepTransportBridgeFactory;
import org.jscep.transport.TransportFactory;
import org.jscep.transport.UrlConnectionTransportFactory;
import org.jscep.transport.response.Capabilities;

/**
 * The <tt>Client</tt> class is used for interacting with a SCEP server.
 * <p>
 * Typical usage might look like so:
 *
 * <pre>
 * // Create the client
 * URL server = new URL(&quot;http://jscep.org/scep/pkiclient.exe&quot;);
 * CertificateVerifier verifier = new ConsoleCertificateVerifier();
 * Client client = new Client(server, verifier);
 *
 * // Invoke operations on the client.
 * client.getCaCapabilities();
 * </pre>
 *
 * Each of the operations of this class is overloaded with a profile argument to
 * support SCEP servers with multiple (or mandatory) profile names.
 */
public final class Client {

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
    private final CallbackHandler handler;
    private CertStoreInspectorFactory inspectorFactory = new DefaultCertStoreInspectorFactory();
    private TransportFactory transportFactory = new UrlConnectionTransportFactory();
    private ScepClient scepClient;

    /**
     * Constructs a new <tt>Client</tt> instance using the provided
     * <tt>CallbackHandler</tt> for the provided URL.
     * <p>
     * The <tt>CallbackHandler</tt> must be able to handle
     * {@link CertificateVerificationCallback}. Unless the
     * <tt>CallbackHandler</tt> will be used to handle additional
     * <tt>Callback</tt>s, users of this class are recommended to use the
     * {@link #Client(URL, CertificateVerifier)} constructor instead.
     *
     * @param url
     *            the URL of the SCEP server.
     * @param handler
     *            the callback handler used to check the CA identity.
     */
    public Client(final URL url, final CallbackHandler handler) {
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
        if (handler == null) {
            throw new NullPointerException(
                    "Callback handler should not be null");
        }

        this.url = url;
        this.handler = handler;
    }

    /**
     * Constructs a new <tt>Client</tt> instance using the provided
     * <tt>CertificateVerifier</tt> for the provided URL.
     *
     * The provided <tt>CertificateVerifier</tt> is used to verify that the
     * identity of the SCEP server matches what the client expects.
     *
     * @param url
     *            the URL of the SCEP server.
     * @param verifier
     *            the verifier used to check the CA identity.
     */
    public Client(final URL url, final CertificateVerifier verifier) {
        this(url, new DefaultCallbackHandler(verifier));
    }

    // INFORMATIONAL REQUESTS

    /**
     * Retrieves the set of SCEP capabilities from the CA.
     *
     * @return the capabilities of the server.
     */
    public Capabilities getCaCapabilities() {
        // NON-TRANSACTIONAL
        return getCaCapabilities(null);
    }

    /**
     * Retrieves the capabilities of the SCEP server.
     * <p>
     * This method provides support for SCEP servers with multiple profiles.
     *
     * @param profile
     *            the SCEP server profile.
     * @return the capabilities of the server.
     */
    public Capabilities getCaCapabilities(final String profile) {
        ResultHolder<Capabilities, RuntimeException> holder =
                new ResultHolder<Capabilities, RuntimeException>
                        (RuntimeException.class);
        client().getCaCapabilities(profile, holder);
        return holder.getResult();
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
     * @return the certificate store.
     * @throws ClientException
     *             if any client error occurs.
     * @see DefaultCertStoreInspectorFactory
     */
    public CertStore getCaCertificate() throws ClientException {
        return getCaCertificate(null);
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
     * @return the certificate store.
     * @throws ClientException
     *             if any client error occurs.
     * @see CertStoreInspector
     */
    public CertStore getCaCertificate(final String profile)
            throws ClientException {
        ResultHolder<CertStore, ClientException> holder =
                new ResultHolder<CertStore, ClientException>
                        (ClientException.class);
        client().getCaCertificate(profile, holder);
        return holder.getResult();
    }

    /**
     * Retrieves the next certificate to be used by the CA.
     * <p>
     * This method will query the SCEP server to determine if the CA is
     * scheduled to start using a new certificate for issuing.
     *
     * @return the certificate store.
     * @throws ClientException
     *             if any client error occurs.
     * @see CertStoreInspector
     */
    public CertStore getRolloverCertificate() throws ClientException {
        return getRolloverCertificate(null);
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
     * @return the certificate store.
     * @throws ClientException
     *             if any client error occurs.
     * @see CertStoreInspector
     */
    public CertStore getRolloverCertificate(final String profile)
            throws ClientException {
        ResultHolder<CertStore, ClientException> holder =
                new ResultHolder<CertStore, ClientException>
                        (ClientException.class);
        client().getRolloverCertificate(profile, holder);
        return holder.getResult();
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
     * @return the CRL corresponding to the issuer and serial.
     * @throws ClientException
     *             if any client errors occurs.
     * @throws OperationFailureException
     *             if the request fails.
     */
    public X509CRL getRevocationList(final X509Certificate identity,
            final PrivateKey key, final X500Principal issuer,
            final BigInteger serial) throws ClientException,
            OperationFailureException {
        return getRevocationList(identity, key, issuer, serial, null);
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
     * @return the CRL corresponding to the issuer and serial.
     * @throws ClientException
     *             if any client errors occurs.
     * @throws OperationFailureException
     *             if the request fails.
     */
    @SuppressWarnings("unchecked")
    public X509CRL getRevocationList(final X509Certificate identity,
            final PrivateKey key, final X500Principal issuer,
            final BigInteger serial, final String profile)
            throws ClientException, OperationFailureException {
        ResultHolder<X509CRL, ClientException> holder =
                new ResultHolder<X509CRL, ClientException>
                        (ClientException.class);
        client().getRevocationList(identity, key, issuer, serial, profile,
                holder);
        return holder.getResult();
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
     * @return the certificate store containing the requested certificate.
     * @throws ClientException
     *             if any client error occurs.
     * @throws OperationFailureException
     *             if the SCEP server refuses to service the request.
     */
    public CertStore getCertificate(final X509Certificate identity,
            final PrivateKey key, final BigInteger serial)
            throws ClientException, OperationFailureException {
        return getCertificate(identity, key, serial, null);
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
     * @return the certificate store containing the requested certificate.
     * @throws ClientException
     *             if any client error occurs.
     * @throws OperationFailureException
     *             if the SCEP server refuses to service the request.
     */
    public CertStore getCertificate(final X509Certificate identity,
            final PrivateKey key, final BigInteger serial, final String profile)
            throws OperationFailureException, ClientException {
        ResultHolder<CertStore, ClientException> holder =
                new ResultHolder<CertStore, ClientException>
                        (ClientException.class);
        client().getCertificate(identity, key, serial, profile, holder);
        return holder.getResult();
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
     * @return the certificate store returned by the server.
     * @throws ClientException
     *             if any client error occurs.
     * @throws TransactionException
     *             if there is a problem with the SCEP transaction.
     * @see CertStoreInspector
     */
    public EnrollmentResponse enrol(final X509Certificate identity,
            final PrivateKey key, final PKCS10CertificationRequest csr)
            throws ClientException, TransactionException {
        return enrol(identity, key, csr, null);
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
     * @param profile
     *            the SCEP server profile.
     * @return the certificate store returned by the server.
     * @throws ClientException
     *             if any client error occurs.
     * @throws TransactionException
     *             if there is a problem with the SCEP transaction.
     * @see CertStoreInspector
     */
    public EnrollmentResponse enrol(final X509Certificate identity,
            final PrivateKey key, final PKCS10CertificationRequest csr,
            final String profile) throws ClientException, TransactionException {
        ResultHolder<EnrollmentResponse, ClientException> holder =
                new ResultHolder<EnrollmentResponse, ClientException>
                        (ClientException.class);
        client().enrol(identity, key, csr, profile, holder);
        return holder.getResult();
    }

    public EnrollmentResponse poll(final X509Certificate identity,
            final PrivateKey identityKey, final X500Principal subject,
            final TransactionId transId) throws ClientException,
            TransactionException {
        return poll(identity, identityKey, subject, transId, null);
    }

    public EnrollmentResponse poll(final X509Certificate identity,
            final PrivateKey identityKey, final X500Principal subject,
            final TransactionId transId, final String profile)
            throws ClientException, TransactionException {
        ResultHolder<EnrollmentResponse, ClientException> holder =
                new ResultHolder<EnrollmentResponse, ClientException>
                        (ClientException.class);
        client().poll(identity, identityKey, subject, transId, profile,
                holder);
        return holder.getResult();
    }

    public synchronized void setCertStoreInspectorFactory(
            final CertStoreInspectorFactory inspectorFactory) {
        this.inspectorFactory = inspectorFactory;
    }

    public synchronized void setTransportFactory(
    		final TransportFactory transportFactory) {
    	this.transportFactory = transportFactory;
    }

    private synchronized ScepClient client() {
        if (scepClient == null) {
            scepClient = scepClient()
                    .url(url)
                    .callbackHandler(handler)
                    .certStoreInspectorFactory(inspectorFactory)
                    .transportFactory(new ScepTransportBridgeFactory(transportFactory))
                    .build();
        }
        return scepClient;
    }
}
