package org.jscep.server;


import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.jscep.transaction.TransactionId;
import org.jscep.transport.response.Capability;

final class ScepServletCa implements CertificateAuthority {

    private final ScepServlet servlet;

    ScepServletCa(ScepServlet servlet) {
        this.servlet = servlet;
    }

    @Override
    public Set<Capability> getCapabilities(String identifier) throws Exception {
        return servlet.doCapabilities(identifier);
    }

    @Override
    public List<X509Certificate> getCaCertificate(
            String identifier
    ) throws Exception {
        return servlet.doGetCaCertificate(identifier);
    }

    @Override
    public List<X509Certificate> getNextCaCertificate(
            String identifier
    ) throws Exception {
        return servlet.getNextCaCertificate(identifier);
    }

    @Override
    public List<X509Certificate> getCert(
            X500Name issuer, BigInteger serial
    ) throws Exception {
        return servlet.doGetCert(issuer, serial);
    }

    @Override
    public List<X509Certificate> getCertInitial(
            X500Name issuer, X500Name subject, TransactionId transId
    ) throws Exception {
        return servlet.doGetCertInitial(issuer, subject, transId);
    }

    @Override
    public X509CRL getCrl(X500Name issuer, BigInteger serial) throws Exception {
        return servlet.doGetCrl(issuer, serial);
    }

    @Override
    public List<X509Certificate> enrol(
            PKCS10CertificationRequest certificationRequest,
            X509Certificate sender, TransactionId transId
    ) throws Exception {
        return servlet.doEnrol(certificationRequest, sender, transId);
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
