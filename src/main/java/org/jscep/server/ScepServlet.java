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

import java.io.IOException;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.jscep.transaction.TransactionId;
import org.jscep.transport.response.Capability;

/**
 * This class provides a base Servlet which can be extended using the abstract
 * methods to implement a SCEP CA (or RA).
 */
public abstract class ScepServlet extends HttpServlet {
    /**
     * Serialization ID
     */
    private static final long serialVersionUID = 1L;

    private final ScepServer server = new ScepServer(
            new ScepServletCa(this)
    );

    /**
     * {@inheritDoc}
     */
    @SuppressWarnings("unchecked")
    @Override
    public final void service(final HttpServletRequest req,
            final HttpServletResponse res) throws ServletException, IOException {
        Map<String, String> parameters = new HashMap<String, String>();
        for (Object n : Collections.list(req.getParameterNames())) {
            String name = (String) n;
            parameters.put(name, req.getParameter(name));
        }
        ScepRequest scepRequest = new ScepRequest(
                req.getMethod(),
                IOUtils.toByteArray(req.getInputStream()),
                parameters
        );
        ScepResponse scepResponse = new ScepResponse();

        try {
            server.service(scepRequest, scepResponse);
        } catch (Exception e) {
            throw new ServletException(e);
        }

        res.setStatus(scepResponse.getStatus());
        for (Map.Entry<String, String> entry :
                scepResponse.getHeaders().entrySet()) {
            res.setHeader(entry.getKey(), entry.getValue());
        }
        if (scepResponse.getBody() != null) {
            res.getOutputStream().write(scepResponse.getBody());
            res.getOutputStream().close();
        } else if (scepResponse.getMessage() != null) {
            res.getWriter().write(scepResponse.getMessage());
            res.getWriter().flush();
        }
    }

    /**
     * See {@link CertificateAuthority#getCapabilities}
     */
    protected abstract Set<Capability> doCapabilities(final String identifier)
            throws Exception;

    /**
     * See {@link CertificateAuthority#getCaCertificate}
     */
    protected abstract List<X509Certificate> doGetCaCertificate(
            String identifier) throws Exception;

    /**
     * See {@link CertificateAuthority#getNextCaCertificate}
     */
    protected abstract List<X509Certificate> getNextCaCertificate(
            String identifier) throws Exception;

    /**
     * See {@link CertificateAuthority#getCert}
     */
    protected abstract List<X509Certificate> doGetCert(final X500Name issuer,
            final BigInteger serial) throws Exception;

    /**
     * See {@link CertificateAuthority#getCertInitial}
     */
    protected abstract List<X509Certificate> doGetCertInitial(
            final X500Name issuer, final X500Name subject,
            final TransactionId transId) throws Exception;

    /**
     * See {@link CertificateAuthority#getCrl}
     */
    protected abstract X509CRL doGetCrl(final X500Name issuer,
            final BigInteger serial) throws Exception;

    /**
     * See {@link CertificateAuthority#enrol}
     */
    protected abstract List<X509Certificate> doEnrol(
            final PKCS10CertificationRequest certificationRequest,
            final X509Certificate sender,
            final TransactionId transId) throws Exception;

    /**
     * See {@link CertificateAuthority#getRecipientKey}
     */
    protected abstract PrivateKey getRecipientKey();

    /**
     * See {@link CertificateAuthority#getRecipient}
     */
    protected abstract X509Certificate getRecipient();

    /**
     * See {@link CertificateAuthority#getSignerKey}
     */
    protected abstract PrivateKey getSignerKey();

    /**
     * See {@link CertificateAuthority#getSigner}
     */
    protected abstract X509Certificate getSigner();
    
    /**
     * See {@link CertificateAuthority#getSignerCertificateChain}
     */
    protected abstract X509Certificate[] getSignerCertificateChain();
}
