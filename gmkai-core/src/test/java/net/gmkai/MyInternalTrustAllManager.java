package net.gmkai;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class MyInternalTrustAllManager implements InternalX509TrustManager {

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {

    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {

    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        throw new UnsupportedOperationException();
    }
}
