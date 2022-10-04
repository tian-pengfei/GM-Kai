package net.gmkai;

import net.gmkai.crypto.TLSCrypto;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.X509ExtendedKeyManager;
import java.net.Socket;
import java.security.SecureRandom;

public class InternalContextData {

    // TLCP--> InternalX509KeyManager  TLS-->InternalX509KeyManager
    private final InternalKeyManager keyManager;

    private final InternalX509TrustManager trustManager;

    private final SecureRandom secureRandom;

    private final TLSCrypto tlsCrypto;

    private final SSLSessionContext serverSSLSessionContext;

    private final SSLSessionContext clientSSLSessionContext;


    private InternalContextData(InternalKeyManager keyManager,
                                InternalX509TrustManager trustManager,
                                SecureRandom secureRandom,
                                TLSCrypto tlsCrypto,
                                SSLSessionContext serverSSLSessionContext,
                                SSLSessionContext clientSSLSessionContext) {

        this.keyManager = keyManager;
        this.trustManager = trustManager;
        this.secureRandom = secureRandom;
        this.serverSSLSessionContext = serverSSLSessionContext;
        this.clientSSLSessionContext = clientSSLSessionContext;
        this.tlsCrypto = tlsCrypto;
    }

    public InternalKeyManager getKeyManager() {
        return keyManager;
    }

    public InternalX509TrustManager getTrustManager() {
        return trustManager;
    }

    public SecureRandom getSecureRandom() {
        return secureRandom;
    }

    public SSLSessionContext getServerSSLSessionContext() {
        return serverSSLSessionContext;
    }

    public SSLSessionContext getClientSSLSessionContext() {
        return clientSSLSessionContext;
    }

    public static InternalContextData getInstance(ContextData contextData, Socket socket) {
        InternalKeyManager internalKeyManager = getInternalKeyManager(contextData.getKeyManager(), socket);
        InternalX509TrustManager internalTrustManager = InternalX509TrustManager.
                getInstance(contextData.getX509TrustManager(), socket);

        return new InternalContextData(
                internalKeyManager,
                internalTrustManager,
                contextData.getSecureRandom(),
                contextData.getTLSCrypto(),
                contextData.getServerSSLSessionConText(),
                contextData.getClientSSLSessionConText());
    }

    public static InternalContextData getInstance(ContextData contextData, SSLEngine sslEngine) {
        InternalKeyManager internalKeyManager = getInternalKeyManager(contextData.getKeyManager(), sslEngine);
        InternalX509TrustManager internalTrustManager = InternalX509TrustManager.
                getInstance(contextData.getX509TrustManager(), sslEngine);

        return new InternalContextData(
                internalKeyManager,
                internalTrustManager,
                contextData.getSecureRandom(),
                contextData.getTLSCrypto(),
                contextData.getServerSSLSessionConText(),
                contextData.getClientSSLSessionConText());
    }

    private static InternalKeyManager getInternalKeyManager(KeyManager keyManager, Socket socket) {

        if (keyManager instanceof X509ExtendedKeyManager) {
            return InternalX509KeyManager.getInstance((X509ExtendedKeyManager) keyManager, socket);
        }
        if (keyManager instanceof TLCPX509KeyManager) {
            return InternalTLCPX509KeyManager.getInstance((TLCPX509KeyManager) keyManager, socket);
        }
        throw new UnsupportedOperationException("not support the type of this key-manager");
    }

    private static InternalKeyManager getInternalKeyManager(KeyManager keyManager, SSLEngine sslEngine) {

        if (keyManager instanceof X509ExtendedKeyManager) {
            return InternalX509KeyManager.getInstance((X509ExtendedKeyManager) keyManager, sslEngine);
        }
        if (keyManager instanceof TLCPX509KeyManager) {
            return InternalTLCPX509KeyManager.getInstance((TLCPX509KeyManager) keyManager, sslEngine);
        }
        throw new UnsupportedOperationException("not support the type of this key-manager");
    }


    public TLSCrypto getTLSCrypto() {
        return tlsCrypto;
    }
}
