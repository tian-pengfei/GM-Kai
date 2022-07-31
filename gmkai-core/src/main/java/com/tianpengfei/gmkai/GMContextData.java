package com.tianpengfei.gmkai;

public class GMContextData {

    private final GMSSLContextSpi context;

    private final GMX509KeyManager x509KeyManager;

    private final GMX509TrustManager x509TrustManager;

    private final GMSessionContext clientSessionContext;

    private final GMSessionContext serverSessionContext;

    public GMContextData(GMSSLContextSpi context, GMX509KeyManager x509KeyManager, GMX509TrustManager trustManager, GMSessionContext clientSessionContext, GMSessionContext serverSessionContext) {

        this.context = context;

        this.x509KeyManager = x509KeyManager;

        this.x509TrustManager = trustManager;

        this.clientSessionContext = clientSessionContext;

        this.serverSessionContext = serverSessionContext;
    }

    public GMSSLContextSpi getContext() {
        return context;
    }

    public GMX509KeyManager getX509KeyManager() {
        return x509KeyManager;
    }

    public GMX509TrustManager getTrustManager() {
        return x509TrustManager;
    }

    public GMSessionContext getClientSessionContext() {
        return clientSessionContext;
    }

    public GMSessionContext getServerSessionContext() {
        return serverSessionContext;
    }

}
