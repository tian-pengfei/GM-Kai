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


    GMContextData contextData;

    @Override
    protected void engineInit(KeyManager[] km, TrustManager[] tm, SecureRandom sr) throws KeyManagementException {

        GMX509KeyManager keyManager = (GMX509KeyManager) Arrays.stream(tm)
                .filter(trustManager1 -> trustManager1 instanceof GMX509KeyManager).
                        findFirst().orElse(null);

        GMX509TrustManager trustManager = (GMX509TrustManager) Arrays.stream(tm)
                .filter(trustManager1 -> trustManager1 instanceof GMX509TrustManager)
                .findFirst().orElse(null);
        GMSessionContext clientSessionContext = new GMSessionContext();
        GMSessionContext serverSessionContext = new GMSessionContext();

        contextData = new GMContextData(this, keyManager, trustManager, clientSessionContext, serverSessionContext);


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

    GMSSLParameters getSupportedSSLParameters(boolean isClient) {

        return new GMSSLParameters(this, getDefaultProtocols(isClient), getDefaultCipherSuites(isClient));
    }


    public List<ProtocolVersion> getSupportedProtocols(boolean isClientMode) {
        return Lists.newArrayList(ProtocolVersion.GMSSL11);
    }
}
