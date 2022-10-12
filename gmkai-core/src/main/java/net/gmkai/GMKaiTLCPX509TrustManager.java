package net.gmkai;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedTrustManager;
import java.net.Socket;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Objects;

//simple implementation
//todo complete
public class GMKaiTLCPX509TrustManager extends X509ExtendedTrustManager {


    List<X509Certificate> trustedCerts;

    GMKaiTLCPX509TrustManager(List<X509Certificate> trustedCerts) {
        this.trustedCerts = trustedCerts;
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
        checkTrust(chain, authType);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
        checkTrust(chain, authType);
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
        checkTrust(chain, authType);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
        checkTrust(chain, authType);
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        checkClientTrusted(chain, authType, (Socket) null);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        checkServerTrusted(chain, authType, (Socket) null);
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return trustedCerts.toArray(new X509Certificate[0]);
    }

    private void checkTrust(X509Certificate[] chain, String authType) throws CertificateException {

        if (Objects.isNull(chain) || chain.length < 2) {
            throw new CertificateException("the lack of the certificate");
        }
        X509Certificate sigCert = chain[0];
        X509Certificate encCert = chain[1];
        if (checkTrust(sigCert) && checkTrust(encCert)) return;

        throw new CertificateException("dont trust these certificates");
    }

    private boolean checkTrust(X509Certificate cert) throws CertificateException {
        cert.checkValidity();

        if (Objects.isNull(trustedCerts) || trustedCerts.isEmpty()) {
            throw new CertificateException("no trust anchors");
        }

        for (X509Certificate trustCert : trustedCerts) {

            try {
                cert.verify(trustCert.getPublicKey());
                return true;
            } catch (Exception ignore) {
            }
        }
        return false;
    }
}
