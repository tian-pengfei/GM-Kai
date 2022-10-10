package net.gmkai;

import com.google.common.collect.Lists;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import test.TestHelper;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertThrowsExactly;

public class GMKaiTLCPX509TrustManagerTest {

    private GMKaiTLCPX509TrustManager gmKaiTLCPX509TrustManager;

    private X509Certificate[] chain;

    @BeforeEach
    public void setUp() throws CertificateException, NoSuchProviderException, IOException, KeyStoreException, NoSuchAlgorithmException {

        List<X509Certificate> trustedCerts = Lists.newArrayList(TestHelper.
                getX509CertificateFromPEM("src/test/resources/sm2.oca.pem"));
        gmKaiTLCPX509TrustManager = new GMKaiTLCPX509TrustManager(trustedCerts);
        KeyStore sm2KeyStore = TestHelper.getKeyStore("src/test/resources/sm2.gmkai.pfx", "12345678");

        chain = new X509Certificate[]{(X509Certificate) sm2KeyStore.getCertificate("sig"),
                (X509Certificate) sm2KeyStore.getCertificate("enc")};

    }

    @Test
    public void should_client_trusted() throws CertificateException {
        gmKaiTLCPX509TrustManager.checkClientTrusted(chain, "UNKNOWN");
    }

    @Test
    public void should_server_trusted() throws CertificateException {
        gmKaiTLCPX509TrustManager.checkServerTrusted(chain, "UNKNOWN");
    }

    @Test
    public void should_throw_exception_by_untrusted_certs() throws CertificateException, IOException, NoSuchProviderException {
        X509Certificate untrustedCert = TestHelper.
                getX509CertificateFromPEM("src/test/resources/untrusted.cert.pem");

        chain = new X509Certificate[]{untrustedCert, chain[0]};

        assertThrowsExactly(CertificateException.class,
                () -> gmKaiTLCPX509TrustManager.checkServerTrusted(chain, "UNKNOWN"));
    }

    @Test
    public void should_throw_exception_by_lack_of_certs() {

        chain = new X509Certificate[]{chain[0]};

        assertThrowsExactly(CertificateException.class,
                () -> gmKaiTLCPX509TrustManager.checkServerTrusted(chain, "UNKNOWN"));
    }

    @Test
    public void should_throw_exception_by_not_having_trust_certs() {

        gmKaiTLCPX509TrustManager = new GMKaiTLCPX509TrustManager(Lists.newArrayList());
        assertThrowsExactly(CertificateException.class,
                () -> gmKaiTLCPX509TrustManager.checkServerTrusted(chain, "UNKNOWN"));
    }

}
