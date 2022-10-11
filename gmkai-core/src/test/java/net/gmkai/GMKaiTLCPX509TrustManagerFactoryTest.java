package net.gmkai;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import test.TestHelper;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.notNullValue;

public class GMKaiTLCPX509TrustManagerFactoryTest {

    @Test
    public void should_get_trust_managers() throws KeyStoreException, CertificateException, NoSuchAlgorithmException, NoSuchProviderException, IOException {
        GMKaiTLCPX509TrustManagerFactory trustManagerFactory = new GMKaiTLCPX509TrustManagerFactory();
        KeyStore keyStore = TestHelper.getKeyStore("src/test/resources/sm2.gmkai.pfx", "12345678");
        trustManagerFactory.engineInit(keyStore);
        assertThat(trustManagerFactory.engineGetTrustManagers(), notNullValue());
    }

    @Test
    public void should_get_trust_managers_with_null_key_store() throws KeyStoreException {
        GMKaiTLCPX509TrustManagerFactory trustManagerFactory = new GMKaiTLCPX509TrustManagerFactory();
        trustManagerFactory.engineInit((KeyStore) null);
        assertThat(trustManagerFactory.engineGetTrustManagers(), notNullValue());
    }

    @Test
    public void should_throw_when_havent_initialized() {
        GMKaiTLCPX509TrustManagerFactory trustManagerFactory = new GMKaiTLCPX509TrustManagerFactory();
        Assertions.assertThrowsExactly(IllegalStateException.class,
                trustManagerFactory::engineGetTrustManagers);
    }

}
