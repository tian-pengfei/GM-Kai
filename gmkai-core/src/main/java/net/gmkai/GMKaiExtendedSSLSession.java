package net.gmkai;

import javax.net.ssl.ExtendedSSLSession;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLSession;
import java.security.cert.Certificate;
import java.util.Collections;
import java.util.List;


public interface GMKaiExtendedSSLSession extends SSLSession {

    String[] getLocalSupportedSignatureAlgorithms();

    String[] getPeerSupportedSignatureAlgorithms();

    default List<SNIServerName> getRequestedServerNames() {
        throw new UnsupportedOperationException();
    }

    default List<byte[]> getStatusResponses() {
        return Collections.emptyList();
    }

    boolean isFipsMode();


    //----------------------------------------------------//

    ExtendedSSLSession toExtendedSSLSession();

    void putMasterSecret(byte[] masterSecret);

    byte[] getMasterSecret();

    void putPeerCertificate(Certificate[] peerCerts);

    void putLocalCertificate(Certificate[] localCerts);

}
