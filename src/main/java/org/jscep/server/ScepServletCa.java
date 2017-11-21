package org.jscep.server;


import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.jscep.transaction.TransactionId;

final class ScepServletCa implements CertificateAuthority {

    private final ScepServlet servlet;

    ScepServletCa(ScepServlet servlet) {
        this.servlet = servlet;
    }

    @Override
    public void getCapabilities(String identifier, ScepResponseBuilder builder)
            throws Exception {
        builder.capabilities(servlet.doCapabilities(identifier));
    }

    @Override
    public void getCaCertificate(String identifier, ScepResponseBuilder builder)
            throws Exception {
        builder.caCertificate(servlet.doGetCaCertificate(identifier));
    }

    @Override
    public void getNextCaCertificate(
            String identifier, ScepResponseBuilder builder
    ) throws Exception {
        builder.nextCaCertificate(servlet.getNextCaCertificate(identifier));
    }

    @Override
    public void getCert(
            X500Name issuer, BigInteger serial, ScepResponseBuilder builder
    ) throws Exception {
        builder.foundCertificate(servlet.doGetCert(issuer, serial));
    }

    @Override
    public void getCertInitial(
            X500Name issuer, X500Name subject,
            TransactionId transId, ScepResponseBuilder builder
    ) throws Exception {
        builder.issuedCertificate(
                servlet.doGetCertInitial(issuer, subject, transId)
        );
    }

    @Override
    public void getCrl(
            X500Name issuer, BigInteger serial, ScepResponseBuilder builder
    ) throws Exception {
        builder.crl(servlet.doGetCrl(issuer, serial));
    }

    @Override
    public void enrol(
            PKCS10CertificationRequest certificationRequest,
            X509Certificate sender, TransactionId transId,
            ScepResponseBuilder builder
    ) throws Exception {
        builder.issuedCertificate(
                servlet.doEnrol(certificationRequest, sender, transId)
        );
    }

    @Override
    public PrivateKey getRecipientKey() {
        return servlet.getRecipientKey();
    }

    @Override
    public X509Certificate getRecipient() {
        return servlet.getRecipient();
    }

    @Override
    public PrivateKey getSignerKey() {
        return servlet.getSignerKey();
    }

    @Override
    public X509Certificate getSigner() {
        return servlet.getSigner();
    }

    @Override
    public X509Certificate[] getSignerCertificateChain() {
        return servlet.getSignerCertificateChain();
    }
}
