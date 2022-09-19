package net.gmkai;

import net.gmkai.crypto.TLSCrypto;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLSession;
import java.security.cert.X509Certificate;

public interface HandshakeContext {

    SSLSession getHandshakeSession();

    boolean isClientMode();

    InternalX509TrustManager getX509TrustManager();

    KeyManager getKeyManager();

    void setPeerCertChain(X509Certificate[] chain);

    void setLocalCertChain(X509Certificate[] chain);

    X509Certificate[] getPeerCertChain();

    X509Certificate[] getLocalCertChain();

    TLSCipherSuite getCurrentCipherSuite();

    ProtocolVersion getCurrentProtocol();

    byte[] getClientRandom();

    byte[] getServerRandom();

    TLSCrypto getTLSCrypto();

    void setPreMasterSecret(byte[] preMasterSecret);

    byte[] getPreMasterSecret();

    void setMasterSecret(byte[] masterSecret);
}
