package com.tianpengfei.gmkai;

import javax.net.ssl.*;
import java.security.KeyManagementException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;

public class GMSSLContextSpi extends SSLContextSpi {

    private static final List<ProtocolVersion> supportedProtocols;
    private static final List<ProtocolVersion> serverDefaultProtocols;

    private static final List<CipherSuite> supportedCipherSuites;
    private static final List<CipherSuite> serverDefaultCipherSuites;

    static {
        supportedProtocols = Arrays.asList(
                ProtocolVersion.PROTOCOLS_OF_GMSSLs
        );
        serverDefaultProtocols = Arrays.asList(
                ProtocolVersion.PROTOCOLS_OF_GMSSLs
        );


        supportedCipherSuites = Arrays.asList(
                CipherSuite.values()
        );
        serverDefaultCipherSuites = Arrays.asList(
                CipherSuite.values()
        );

    }


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
