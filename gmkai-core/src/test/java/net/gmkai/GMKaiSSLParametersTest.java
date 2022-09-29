package net.gmkai;

import com.google.common.collect.ImmutableList;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static net.gmkai.ProtocolVersion.*;
import static net.gmkai.ProtocolVersion.TLCP11;
import static net.gmkai.TLSCipherSuite.*;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;

public class GMKaiSSLParametersTest {

    private GMKaiSSLParameters sslParameters;


    @BeforeEach
    public void setUp() {
        sslParameters = new GMKaiSSLParameters(
                true,
                ImmutableList.of(TLCP11, TLS12),
                ImmutableList.of(ECC_SM4_CBC_SM3, RSA_SM4_CBC_SHA256),

                ImmutableList.of(TLCP11),
                ImmutableList.of(RSA_SM4_CBC_SHA256),

                ImmutableList.of(TLCP11, TLS12),
                ImmutableList.of(ECC_SM4_CBC_SM3, RSA_SM4_CBC_SHA256)
        );
    }


    @Test
    public void should_set_enabled_protocols() {

        sslParameters.setEnabledProtocols(ImmutableList.of(TLS12));

        assertThat(sslParameters.getEnabledProtocols(),
                is(equalTo(ImmutableList.of(TLS12))));
    }

    @Test
    public void should_set_enabled_cipher_suite() {

        sslParameters.setEnabledCipherSuites(ImmutableList.of(ECC_SM4_CBC_SM3));

        assertThat(sslParameters.getEnableCipherSuites(),
                is(equalTo(ImmutableList.of(ECC_SM4_CBC_SM3))));
    }

    @Test
    public void should_throw_exception_for_not_supported_protocol() {

        Assertions.assertThrowsExactly(IllegalArgumentException.class,
                () -> sslParameters.setEnabledProtocols(ImmutableList.of(TLS13)));
    }

    @Test
    public void should_throw_exception_for_not_supported_cipher_suite() {

        Assertions.assertThrowsExactly(IllegalArgumentException.class,
                () -> sslParameters.setEnabledCipherSuites(ImmutableList.of(ECDHE_SM4_CBC_SM3)));
    }

    @Test
    public void should_change_client_mode() {

        sslParameters.setUseClientMode(false);

        assertThat(sslParameters.getEnabledProtocols(),
                is(equalTo(ImmutableList.of(TLCP11))));

        assertThat(sslParameters.getEnableCipherSuites(),
                is(equalTo(ImmutableList.of(RSA_SM4_CBC_SHA256))));

    }

    @Test
    public void should_change_client_mode_after_modified_enable_protocols() {
        sslParameters.setEnabledProtocols(ImmutableList.of(TLS12));

        sslParameters.setEnabledCipherSuites(ImmutableList.of(RSA_SM4_CBC_SHA256));

        sslParameters.setUseClientMode(false);

        assertThat(sslParameters.getEnabledProtocols(),
                is(equalTo(ImmutableList.of(TLS12))));

        assertThat(sslParameters.getEnableCipherSuites(),
                is(equalTo(ImmutableList.of(RSA_SM4_CBC_SHA256))));
    }

}
