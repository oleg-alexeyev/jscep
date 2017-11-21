package org.jscep.server;


import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.jscep.transaction.OperationFailureException;
import org.jscep.transaction.TransactionId;

/**
 * <p>Certificate Authority operations.</p>
 *
 * <p>Each operation accepts needed parameters, performs the operation and
 * passes the result to the given response builder. This provides for
 * different implementations - synchronous or asynchronous,
 * blocking or non-blocking.</p>
 *
 * <p>In case of an error, each operation may either throw an exception or
 * call {@link ScepResponseBuilder#error(Throwable)}. This allows
 * error handling in the most handy way for the target environment,
 * throwing in a blocking one, passing to the builder in a non-blocking.</p>
 *
 * <p>In case some passed data is invalid, for example password is wrong or
 * some data is improperly encoded,
 * {@link ScepResponseBuilder#badRequest(String)} can be used providing
 * details in the message. The
 * {@link ScepResponseBuilder#badRequest(String, Throwable)
 * version with Throwable cause} will also log the cause.
 * </p>
 */
public interface CertificateAuthority {

    /**
     * Gets the capabilities of the specified CA and
     * passes them to {@link ScepResponseBuilder#capabilities(Set)}.
     *
     * @param identifier
     *            the CA identifier, which may be an empty string.
     * @param builder
     *            SCEP response builder
     * @throws Exception
     *            if any problem occurs
     */
    void getCapabilities(String identifier, ScepResponseBuilder builder)
            throws Exception;

    /**
     * Gets the certificate chain of the specified CA and
     * passes it to {@link ScepResponseBuilder#caCertificate(List)}.
     *
     * @param identifier
     *            the CA identifier, which may be an empty string.
     * @param builder
     *            SCEP response builder
     * @throws Exception
     *             if any problem occurs
     */
    void getCaCertificate(String identifier, ScepResponseBuilder builder)
            throws Exception;

    /**
     * Gets the chain of the next X.509 certificate which will be used by the
     * specified CA and passes it to
     * {@link ScepResponseBuilder#nextCaCertificate(List)}.
     *
     * @param identifier
     *            the CA identifier, which may be an empty string.
     * @param builder
     *            SCEP response builder
     * @throws Exception
     *             if any problem occurs
     */
    void getNextCaCertificate(String identifier, ScepResponseBuilder builder)
            throws Exception;

    /**
     * Retrieve the certificate chain identified by the given parameters and
     * passes it to {@link ScepResponseBuilder#foundCertificate(List)}.
     *
     * If not found, this method should pass null or an empty list to the
     * builder.
     *
     * @param issuer
     *            the issuer name.
     * @param serial
     *            the serial number.
     * @param builder
     *            SCEP response builder
     * @throws OperationFailureException
     *             if the operation cannot be completed
     * @throws Exception
     *             if any problem occurs
     */
    void getCert(
            X500Name issuer, BigInteger serial,
            ScepResponseBuilder builder
    )
            throws Exception;

    /**
     * Checks to see if a previously-requested certificate has been issued. If
     * the certificate has been issued, this method will pass the appropriate
     * certificate chain to {@link ScepResponseBuilder#issuedCertificate(List)}.
     *
     * Otherwise, this method should pass null or an empty list to the
     * builder to indicate that the request is still pending.
     *
     * @param issuer
     *            the issuer name.
     * @param subject
     *            the subject name.
     * @param transId
     *            the transaction ID.
     * @param builder
     *            SCEP response builder
     * @throws OperationFailureException
     *             if the operation cannot be completed
     * @throws Exception
     *             if any problem occurs
     */
    void getCertInitial(
            X500Name issuer, X500Name subject, TransactionId transId,
            ScepResponseBuilder builder
    ) throws Exception;

    /**
     * Retrieve the CRL covering the given certificate identifiers and
     * passes it to {@link ScepResponseBuilder#crl(X509CRL)}.
     *
     * @param issuer
     *            the certificate issuer.
     * @param serial
     *            the certificate serial number.
     * @param builder
     *            SCEP response builder
     * @throws OperationFailureException
     *             if the operation cannot be completed
     * @throws Exception
     *             if any problem occurs
     */
    void getCrl(X500Name issuer, BigInteger serial, ScepResponseBuilder builder)
            throws Exception;

    /**
     * Enrols a certificate into the PKI represented by this SCEP interface. If
     * the request can be completed immediately, this method passes an
     * appropriate certificate chain to
     * {@link ScepResponseBuilder#issuedCertificate(List)}.
     *
     * If the request is pending, this method should pass null or an empty list
     * to the builder.
     *
     * @param certificationRequest
     *            the PKCS #10 CertificationRequest
     * @param transId
     *            the transaction ID
     * @throws OperationFailureException
     *             if the operation cannot be completed
     * @throws Exception
     *             if any problem occurs
     */
    void enrol(
            PKCS10CertificationRequest certificationRequest,
            X509Certificate sender,
            TransactionId transId,
            ScepResponseBuilder builder
    ) throws Exception;

    /**
     * Returns the private key of the recipient entity represented by this SCEP
     * server.
     *
     * @return the private key.
     */
    PrivateKey getRecipientKey();

    /**
     * Returns the certificate of the server recipient entity.
     *
     * @return the certificate.
     */
    X509Certificate getRecipient();

    /**
     * Returns the private key of the entity represented by this SCEP server.
     *
     * @return the private key.
     */
    PrivateKey getSignerKey();

    /**
     * Returns the certificate of the entity represented by this SCEP server.
     *
     * @return the certificate.
     */
    X509Certificate getSigner();

    /**
     * Returns the certificate chain of the entity represented by this SCEP server.
     *
     * @return the chain
     */
    X509Certificate[] getSignerCertificateChain();
}