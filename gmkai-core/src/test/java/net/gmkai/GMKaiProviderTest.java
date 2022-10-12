package net.gmkai;

import org.junit.jupiter.api.Test;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.security.NoSuchAlgorithmException;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.notNullValue;

public class GMKaiProviderTest {


    @Test
    public void should_not_null() throws NoSuchAlgorithmException {

        assertThat(SSLContext.getInstance("TLCP", new GMKaiProvider()), notNullValue());

        assertThat(TrustManagerFactory.getInstance("TLCPX509", new GMKaiProvider()), notNullValue());

        assertThat(KeyManagerFactory.getInstance("TLCPX509", new GMKaiProvider()), notNullValue());

    }
}
