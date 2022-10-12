package net.gmkai;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.KeyManagementException;
import java.security.SecureRandom;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.notNullValue;

public class GMKaiSSLContextSpiTest {

    private GMKaiSSLContextSpi gmKaiSSLContextSpi;

    @BeforeEach
    private void setUp() {
        gmKaiSSLContextSpi = new GMKaiSSLContextSpi();
    }

    @Test
    public void should_not_null() throws KeyManagementException {

        gmKaiSSLContextSpi.engineInit(null, null, new SecureRandom());
        assertThat(gmKaiSSLContextSpi.engineGetClientSessionContext(), notNullValue());
        assertThat(gmKaiSSLContextSpi.engineGetServerSessionContext(), notNullValue());
        assertThat(gmKaiSSLContextSpi.engineGetDefaultSSLParameters(), notNullValue());
        assertThat(gmKaiSSLContextSpi.engineGetServerSocketFactory(), notNullValue());
        assertThat(gmKaiSSLContextSpi.engineGetSocketFactory(), notNullValue());
    }


}
