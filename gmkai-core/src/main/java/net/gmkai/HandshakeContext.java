package net.gmkai;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLSession;
import java.security.cert.X509Certificate;

public interface HandshakeContext {

    SSLSession getHandshakeSession();

    boolean isClientMode();

    InternalX509TrustManager getX509TrustManager();

    KeyManager getKeyManager() ;

    void setPeerCertChain(X509Certificate[] chain);


    void setLocalCertChain(X509Certificate[] chain);

    TLSCipherSuite getCurrentCipherSuite() ;

}
