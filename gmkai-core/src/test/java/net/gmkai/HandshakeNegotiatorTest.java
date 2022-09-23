package net.gmkai;

import com.google.common.collect.Lists;
import net.gmkai.util.Hexs;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import test.ZeroSecureRandom;

import java.io.IOException;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class HandshakeNegotiatorTest {


    HandshakeMsgTransport handshakeMsgTransport;

    PreHandshakeContext preHandshakeContext;

    @BeforeEach
    public void setUp() {

        this.preHandshakeContext = mock(PreHandshakeContext.class);

        this.handshakeMsgTransport = mock(HandshakeMsgTransport.class);

        when(preHandshakeContext.getSupportTLSCipherSuites()).thenReturn(Lists.newArrayList(
                TLSCipherSuite.ECC_SM4_CBC_SM3));

        when(preHandshakeContext.getSecureRandom()).thenReturn(new ZeroSecureRandom());

        when(preHandshakeContext.getSupportCompressionMethods()).thenReturn(Lists.newArrayList(
                CompressionMethod.NULL));
    }

    TLSText client_hello_handshake_msg = new TLSText(
            ContentType.HANDSHAKE,
            ProtocolVersion.TLCP11,
            Hexs.decode(
                    "      01 00 00 2b 01 01 00 00 00 00 00 00 00 00 00 00\n" +
                            "   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00\n" +
                            "   00 00 00 00 00 00 00 00 04 e0 13 e0 11 01 00"));


    TLSText server_hello_handshake_msg = new TLSText(
            ContentType.HANDSHAKE,
            ProtocolVersion.TLCP11,
            Hexs.decode(
                    "      02 00 00 2a 01 01 00 00 00 00 00 00 00 00 00 00\n" +
                            "   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00\n" +
                            "   00 00 00 00 00 00 04 00 00 00 00 e0 13 00"));

    public NegotiationResult expectedNegotiationResult = new NegotiationResult(
            ProtocolVersion.TLCP11,
            new byte[32],
            new byte[32],
            new byte[4],
            TLSCipherSuite.ECC_SM4_CBC_SM3, false);

    @Test
    public void should_client_kick_start_to_tlcp11_server() throws IOException {
        when(handshakeMsgTransport.readHandshakeMsg()).thenReturn(server_hello_handshake_msg);
        HandshakeNegotiator handshakeNegotiator = new HandshakeNegotiator(handshakeMsgTransport);
        when(preHandshakeContext.isClientMode()).thenReturn(true);
        NegotiationResult negotiationResult = handshakeNegotiator.kickStart(preHandshakeContext);
        assertThat(negotiationResult, is(expectedNegotiationResult));

    }

    @Test
    public void should_server_kick_start_to_tlcp11_client() throws IOException {

        when(handshakeMsgTransport.readHandshakeMsg()).thenReturn(client_hello_handshake_msg);
        HandshakeNegotiator handshakeNegotiator = new HandshakeNegotiator(handshakeMsgTransport);
        when(preHandshakeContext.isClientMode()).thenReturn(false);
        NegotiationResult negotiationResult = handshakeNegotiator.kickStart(preHandshakeContext);
        assertThat(negotiationResult, is(expectedNegotiationResult));
    }
}