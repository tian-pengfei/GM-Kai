package net.gmkai;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;
import java.net.Socket;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;


public interface InternalX509TrustManager extends X509TrustManager {


    static InternalX509TrustManager getInstance(X509ExtendedTrustManager x509ExtendedTrustManager, Socket socket) {

        return new InternalX509TrustManager() {
            @Override
            public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {

                x509ExtendedTrustManager.checkClientTrusted(chain, authType, socket);
            }

            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                x509ExtendedTrustManager.checkServerTrusted(chain, authType, socket);
            }

            @Override
            public X509Certificate[] getAcceptedIssuers() {
                return x509ExtendedTrustManager.getAcceptedIssuers();
            }
        };
    }

    static InternalX509TrustManager getInstance(X509ExtendedTrustManager x509ExtendedTrustManager, SSLEngine sslEngine) {

        return new InternalX509TrustManager() {
            @Override
            public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {

                x509ExtendedTrustManager.checkClientTrusted(chain, authType, sslEngine);
            }

            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                x509ExtendedTrustManager.checkServerTrusted(chain, authType, sslEngine);
            }

            @Override
            public X509Certificate[] getAcceptedIssuers() {
                return x509ExtendedTrustManager.getAcceptedIssuers();
            }
        };
    }

}
