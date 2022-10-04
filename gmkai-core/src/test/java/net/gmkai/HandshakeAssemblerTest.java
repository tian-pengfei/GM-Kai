package net.gmkai;

import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLException;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.jupiter.api.Assertions.assertThrowsExactly;

public class HandshakeAssemblerTest {

    private  static final GMKaiExtendedSSLSession sslSession = new GMKaiSSLSession(
            new byte[]{0,0,0,0,0,0},
            "0.0.0.0",
            -1,
            TLSCipherSuite.ECC_SM4_CBC_SM3,
            CompressionMethod.NULL
    );
    @Test
    public void should_assemble() throws SSLException {

        NegotiationResult negotiationResult = new NegotiationResult(
                sslSession,
                ProtocolVersion.TLCP11,
                new byte[32],
                new byte[32],
                new byte[4],
                TLSCipherSuite.ECC_SM4_CBC_SM3, false);

        HandshakeAssembler handshakeExecutor = new HandshakeAssembler();

        HandshakeNodes handshakeNodes = handshakeExecutor.assemble(negotiationResult);

        assertThat(handshakeNodes, is(notNullValue()));

        assertThat(handshakeNodes.getId(), is(negotiationResult.id));
    }

    @Test
    public void should_assemble_by_no_identify_result() throws SSLException {

        NegotiationResult negotiationResult = new NegotiationResult(
                sslSession,
                ProtocolVersion.NULL,
                new byte[32],
                new byte[32],
                new byte[4],
                TLSCipherSuite.ECC_SM4_CBC_SM3, false);

        HandshakeAssembler handshakeExecutor = new HandshakeAssembler();

        assertThrowsExactly(SSLException.class,
                () -> handshakeExecutor.assemble(negotiationResult));

    }

}
