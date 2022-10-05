package net.gmkai;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

public class NegotiationResultTest {

    private static final GMKaiExtendedSSLSession sslSession = new GMKaiSSLSession(
            new byte[]{0, 0, 0, 0, 0, 0},
            "0.0.0.0",
            -1,
            TLSCipherSuite.ECC_SM4_CBC_SM3,
            CompressionMethod.NULL
    );

    @Test
    public void should_throw_null_exception_with_null_parameter() {

        Assertions.assertThrowsExactly(NullPointerException.class,

                () -> new NegotiationResult(
                        sslSession,
                        ProtocolVersion.TLCP11,
                        null,
                        null,
                        null, TLSCipherSuite.ECC_SM4_CBC_SM3, false));

    }

    @Test
    public void should_get_result_id_from_negotiation_result() {

        NegotiationResult negotiationResult = new NegotiationResult(
                sslSession,
                ProtocolVersion.TLCP11,
                new byte[32],
                new byte[32],
                new byte[32], TLSCipherSuite.ECC_SM4_CBC_SM3, false);

        assertThat(negotiationResult.id, is(0x00101e013L));

    }
}
