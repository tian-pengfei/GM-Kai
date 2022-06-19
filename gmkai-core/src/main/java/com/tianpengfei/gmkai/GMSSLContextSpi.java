package com.tianpengfei.gmkai;

import javax.net.ssl.*;
import java.security.KeyManagementException;
import java.security.SecureRandom;

public class GMSSLContextSpi extends SSLContextSpi {


    @Override
    protected void engineInit(KeyManager[] km, TrustManager[] tm, SecureRandom sr) throws KeyManagementException {

    }

    @Override
    protected SSLSocketFactory engineGetSocketFactory() {
        return null;
    }

    @Override
    protected SSLServerSocketFactory engineGetServerSocketFactory() {
        return null;
    }

    @Override
    protected SSLEngine engineCreateSSLEngine() {
        return null;
    }

    @Override
    protected SSLEngine engineCreateSSLEngine(String host, int port) {
        return null;
    }

    @Override
    protected SSLSessionContext engineGetServerSessionContext() {
        return null;
    }

    @Override
    protected SSLSessionContext engineGetClientSessionContext() {
        return null;
    }
}
