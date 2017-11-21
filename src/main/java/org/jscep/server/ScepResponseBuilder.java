package org.jscep.server;


import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;

import org.jscep.transport.response.Capability;

/**
 * Encodes SCEP responses.
 */
public interface ScepResponseBuilder {

    /**
     * Encodes the CA capabilities into SCEP response.
     *
     * @param capabilities the capabilities.
     * @see CertificateAuthority#getCapabilities
     */
    void capabilities(Set<Capability> capabilities);

    /**
     * Encodes the CA certificate into SCEP response.
     *
     * @param caCertificate the CA's certificate chain.
     * @see CertificateAuthority#getCaCertificate
     */
    void caCertificate(List<X509Certificate> caCertificate);

    /**
     * Encodes the next CA certificate into SCEP response.
     *
     * @param caCertificate the CA's certificate chain.
     * @see CertificateAuthority#getNextCaCertificate
     */
    void nextCaCertificate(List<X509Certificate> caCertificate);

    /**
     * Encodes found end entity certificate into SCEP response.
     *
     * @param certificate the certificate chain.
     * @see CertificateAuthority#getCert
     */
    void foundCertificate(List<X509Certificate> certificate);

    /**
     * Encodes issued end entity certificate into SCEP response.
     *
     * @param certificate the certificate chain.
     * @see CertificateAuthority#enrol
     * @see CertificateAuthority#getCertInitial
     */
    void issuedCertificate(List<X509Certificate> certificate);

    /**
     * Encodes a CRL into SCEP response.
     *
     * @param crl the CRL.
     * @see CertificateAuthority#getCrl
     */
    void crl(X509CRL crl);

    /**
     * Encodes an error into SCEP response.
     *
     * @param e a Throwable describing the failure.
     */
    void error(Throwable e);

    /**
     * Encodes a bad request error into SCEP response.
     *
     * @param message message describing what's wrong with the request.
     */
    void badRequest(String message);

    /**
     * Encodes a bad request error into SCEP response.
     *
     * @param message message describing what's wrong with the request.
     * @param cause   the error cause.
     */
    void badRequest(String message, Throwable cause);
}