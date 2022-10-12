package net.gmkai;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import test.TestHelper;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.notNullValue;

public class GMKaiTLCPX509KeyManagerFactoryTest {


    private GMKaiTLCPX509KeyManagerFactory gmKaiTLCPX509KeyManagerFactory;
    private KeyStore keyStore;


    @BeforeEach
    public void setUp() throws Exception {
        gmKaiTLCPX509KeyManagerFactory = new GMKaiTLCPX509KeyManagerFactory();
        keyStore = TestHelper.
                getKeyStore("src/test/resources/sm2.gmkai.pfx", "12345678");

    }

    @Test
    public void should_engine_init() throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException {

        gmKaiTLCPX509KeyManagerFactory.engineInit(keyStore, "12345678".toCharArray());
    }

    @Test
    public void should_engine_key_managers() throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException {

        gmKaiTLCPX509KeyManagerFactory.engineInit(keyStore, "12345678".toCharArray());

        assertThat(gmKaiTLCPX509KeyManagerFactory.engineGetKeyManagers(),
                notNullValue());
    }

    @Test
    public void should_engine_key_managers_before_init() throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException {
        Assertions.assertThrowsExactly(IllegalStateException.class,
                gmKaiTLCPX509KeyManagerFactory::engineGetKeyManagers);
    }

}
