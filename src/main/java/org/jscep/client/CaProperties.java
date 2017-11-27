package org.jscep.client;


import java.security.cert.CertStore;

import org.jscep.transport.ResultHandler;
import org.jscep.transport.response.Capabilities;

final class CaProperties {
    private boolean capsRequested;
    private boolean caCertificateRequested;
    private Capabilities caCaps;
    private CertStore caCertStore;
    private Throwable error = null;
    private ResultHandler<CaProperties> handler;

    private CaProperties(Builder builder) {
        ScepClient client = builder.client;
        if (client == null) {
            throw new NullPointerException("client must not be null");
        }
        String profile = builder.profile;
        this.capsRequested = builder.capsRequested;
        this.caCertificateRequested = builder.caCertificateRequested;
        ResultHandler<CaProperties> handler = builder.handler;
        if (handler == null) {
            throw new NullPointerException("handler must not be null");
        }
        this.handler = handler;

        if (capsRequested) {
            client.getCaCapabilities(profile,
                    new ResultHandler<Capabilities>() {
                        @Override
                        public void handle(Capabilities caps, Throwable e) {
                            if (e != null) {
                                error = e;
                            } else {
                                caCaps = caps;
                            }
                            callHandlerIfReady();
                        }
                    }
            );
        }
        if (caCertificateRequested) {
            client.getCaCertificate(profile,
                    new ResultHandler<CertStore>() {
                        @Override
                        public void handle(CertStore store, Throwable e) {
                            if (e != null) {
                                error = e;
                            } else {
                                caCertStore = store;
                            }
                            callHandlerIfReady();
                        }
                    }
            );
        }
    }

    private void callHandlerIfReady() {
        if (error != null) {
            handler.handle(null, error);
        } else {
            if ((!capsRequested || caCaps != null)
                    && (!caCertificateRequested || caCertStore != null)) {
                handler.handle(this, null);
            }
        }
    }

    Capabilities getCaCaps() {
        return caCaps;
    }

    CertStore getCaCertStore() {
        return caCertStore;
    }

    static final class Builder {

        static Builder caProperties(ScepClient client) {
            return new Builder(client);
        }

        private final ScepClient client;
        private String profile;
        private boolean capsRequested = false;
        private boolean caCertificateRequested = false;
        private ResultHandler<CaProperties> handler;

        private Builder(ScepClient client) {
            this.client = client;
        }

        Builder profile(String profile) {
            this.profile = profile;
            return this;
        }

        Builder requestCaps() {
            capsRequested = true;
            return this;
        }

        Builder requestCaCertStore() {
            caCertificateRequested = true;
            return this;
        }

        void whenReady(ResultHandler<CaProperties> handler) {
            this.handler = handler;
            new CaProperties(this);
        }
    }
}