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
import org.jscep.transport.response.Capability;

public interface CertificateAuthority {

    /**
     * Returns the capabilities of the specified CA.
     *
     * @param identifier
     *            the CA identifier, which may be an empty string.
     * @return the capabilities.
     * @throws Exception
     *             if any problem occurs
     */
    Set<Capability> getCapabilities(String identifier) throws Exception;

    /**
     * Returns the certificate chain of the specified CA.
     *
     * @param identifier
     *            the CA identifier, which may be an empty string.
     * @return the CA's certificate.
     * @throws Exception
     *             if any problem occurs
     */
    List<X509Certificate> getCaCertificate(String identifier) throws Exception;

    /**
     * Return the chain of the next X.509 certificate which will be used by the
     * specified CA.
     *
     * @param identifier
     *            the CA identifier, which may be an empty string.
     * @return the list of certificates.
     * @throws Exception
     *             if any problem occurs
     */
    List<X509Certificate> getNextCaCertificate(String identifier)
            throws Exception;

    /**
     * Retrieve the certificate chain identified by the given parameters.
     *
     * @param issuer
     *            the issuer name.
     * @param serial
     *            the serial number.
     * @return the identified certificate, if any.
     * @throws OperationFailureException
     *             if the operation cannot be completed
     * @throws Exception
     *             if any problem occurs
     */
    List<X509Certificate> getCert(X500Name issuer, BigInteger serial)
            throws Exception;

    /**
     * Checks to see if a previously-requested certificate has been issued. If
     * the certificate has been issued, this method will return the appropriate
     * certificate chain. Otherwise, this method should return null or an empty
     * list to indicate that the request is still pending.
     *
     * @param issuer
     *            the issuer name.
     * @param subject
     *            the subject name.
     * @param transId
     *            the transaction ID.
     * @return the identified certificate, if any.
     * @throws OperationFailureException
     *             if the operation cannot be completed
     * @throws Exception
     *             if any problem occurs
     */
    List<X509Certificate> getCertInitial(
            X500Name issuer, X500Name subject, TransactionId transId
    ) throws Exception;

    /**
     * Retrieve the CRL covering the given certificate identifiers.
     *
     * @param issuer
     *            the certificate issuer.
     * @param serial
     *            the certificate serial number.
     * @return the CRL.
     * @throws OperationFailureException
     *             if the operation cannot be completed
     * @throws Exception
     *             if any problem occurs
     */
    X509CRL getCrl(X500Name issuer, BigInteger serial) throws Exception;

    /**
     * Enrols a certificate into the PKI represented by this SCEP interface. If
     * the request can be completed immediately, this method returns an
     * appropriate certificate chain. If the request is pending, this method
     * should return null or any empty list.
     *
     * @param certificationRequest
     *            the PKCS #10 CertificationRequest
     * @param transId
     *            the transaction ID
     * @return the certificate chain, if any
     * @throws OperationFailureException
     *             if the operation cannot be completed
     * @throws Exception
     *             if any problem occurs
     */
    List<X509Certificate> enrol(
            PKCS10CertificationRequest certificationRequest,
            X509Certificate sender,
            TransactionId transId
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