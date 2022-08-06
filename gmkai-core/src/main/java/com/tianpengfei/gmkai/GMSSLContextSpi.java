package com.tianpengfei.gmkai;

import com.google.common.collect.Lists;

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


    GMSSLContextData contextData;

    @Override
    protected void engineInit(KeyManager[] km, TrustManager[] tm, SecureRandom sr) throws KeyManagementException {

        GMX509KeyManager keyManager = (GMX509KeyManager) Arrays.stream(tm)
                .filter(trustManager1 -> trustManager1 instanceof GMX509KeyManager).
                        findFirst().orElse(null);

        GMX509TrustManager trustManager = (GMX509TrustManager) Arrays.stream(tm)
                .filter(trustManager1 -> trustManager1 instanceof GMX509TrustManager)
                .findFirst().orElse(null);
        GMSSLSessionContext clientSessionContext = new GMSSLSessionContext();
        GMSSLSessionContext serverSessionContext = new GMSSLSessionContext();

        contextData = new GMSSLContextData(this, keyManager, trustManager, clientSessionContext, serverSessionContext);


    }

    @Override
    protected SSLSocketFactory engineGetSocketFactory() {

        return new GMSSLSocketFactory(contextData);
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
        return contextData.getServerSessionContext();
    }

    @Override
    protected SSLSessionContext engineGetClientSessionContext() {
        return contextData.getClientSessionContext();
    }


    List<CipherSuite> getDefaultCipherSuites(boolean isClient) {
        return Lists.newArrayList(CipherSuite.ECC_SM4_CBC_SM3);
    }

    List<ProtocolVersion> getDefaultProtocols(boolean isClient) {
        return Lists.newArrayList(ProtocolVersion.GMSSL11);
    }

    List<CipherSuite> getSupportedCipherSuites() {
        return Lists.newArrayList(CipherSuite.ECC_SM4_CBC_SM3);
    }

    GMSSLParameters getSupportedSSLParameters() {

        return new GMSSLParameters(this, getSupportedProtocols(), getSupportedCipherSuites());
    }


    public List<ProtocolVersion> getSupportedProtocols() {
        return Lists.newArrayList(ProtocolVersion.GMSSL11);
    }
}
