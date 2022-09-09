package net.gmkai.util;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.net.ssl.SSLException;
import java.io.ByteArrayInputStream;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class Certificates {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static byte[] x509Certificate2encodedCert(X509Certificate x509Certificate) throws SSLException {
        try {
            return x509Certificate.getEncoded();
        } catch (CertificateEncodingException e) {
            throw new SSLException(e.getMessage(), e);
        }
    }


    public static X509Certificate encodedCert2x509Certificate(byte[] encodedCert) throws SSLException {
        CertificateFactory cf = null;
        try {
            cf = CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);
            return (X509Certificate) cf.generateCertificate(
                    new ByteArrayInputStream(encodedCert));
        } catch (CertificateException | NoSuchProviderException e) {
            throw new SSLException(e.getMessage(), e);
        }
    }


}
