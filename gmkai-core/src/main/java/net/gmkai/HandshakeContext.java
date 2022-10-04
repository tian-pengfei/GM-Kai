package net.gmkai;

import net.gmkai.crypto.TLSCrypto;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLException;
import java.security.cert.X509Certificate;

public interface HandshakeContext {

    boolean isClientMode();

    InternalX509TrustManager getX509TrustManager();

    KeyManager getKeyManager();

    void setPeerCertChain(X509Certificate[] chain);

    void setLocalCertChain(X509Certificate[] chain);

    X509Certificate[] getPeerCertChain() throws SSLException;

    X509Certificate[] getLocalCertChain();

    TLSCipherSuite getCurrentCipherSuite();

    ProtocolVersion getCurrentProtocol();

    byte[] getClientRandom();

    byte[] getServerRandom();

    TLSCrypto getTLSCrypto();

    void setPreMasterSecret(byte[] preMasterSecret);

    byte[] getPreMasterSecret();

    void setMasterSecret(byte[] masterSecret);

    byte[] getMasterSecret();

    TransportHasher getTransportHasher();

    boolean isNeedAuthClient();

    void notifySelfFinished();

    void notifyPeerFinished();

    void changeWriteCipherSpec();

    void generateSecurityParameters();
}
