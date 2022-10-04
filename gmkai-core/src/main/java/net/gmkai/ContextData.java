package net.gmkai;

import net.gmkai.crypto.TLSCrypto;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.X509ExtendedTrustManager;
import java.security.SecureRandom;

public class ContextData {


    private final KeyManager keyManager;

    private final X509ExtendedTrustManager trustManager;

    private final SecureRandom secureRandom;

    private final SSLSessionContext serverSSLSessionContext;

    private final SSLSessionContext clientSSLSessionContext;

    private final TLSCrypto tlsCrypto;

    private final GMKaiSSLParameters defaultServerSSLParameters;

    private final GMKaiSSLParameters defaultClientSSLParameters;


    ContextData(SSLSessionContext serverSSLSessionContext,
                SSLSessionContext clientSSLSessionContext,
                KeyManager keyManager,
                X509ExtendedTrustManager trustManager,
                SecureRandom secureRandom,
                TLSCrypto tlsCrypto,
                GMKaiSSLParameters defaultServerSSLParameters,
                GMKaiSSLParameters defaultClientSSLParameters) {

        this.serverSSLSessionContext = serverSSLSessionContext;

        this.clientSSLSessionContext = clientSSLSessionContext;

        this.keyManager = keyManager;

        this.trustManager = trustManager;

        this.secureRandom = secureRandom;

        this.tlsCrypto = tlsCrypto;

        this.defaultServerSSLParameters = defaultServerSSLParameters;
        this.defaultClientSSLParameters = defaultClientSSLParameters;
    }

    public TLSCrypto getTLSCrypto() {
        return tlsCrypto;
    }

    public X509ExtendedTrustManager getX509TrustManager() {
        return trustManager;
    }

    public KeyManager getKeyManager() {
        return keyManager;
    }

    public GMKaiSSLParameters getDefaultServerSSLParameters() {
        return defaultServerSSLParameters.clone();
    }

    public GMKaiSSLParameters getDefaultClientSSLParameters() {
        return defaultClientSSLParameters.clone();
    }

    public SSLSessionContext getClientSSLSessionConText() {
        return clientSSLSessionContext;
    }

    public SSLSessionContext getServerSSLSessionConText() {
        return serverSSLSessionContext;
    }

    public SecureRandom getSecureRandom() {
        return secureRandom;
    }
}
