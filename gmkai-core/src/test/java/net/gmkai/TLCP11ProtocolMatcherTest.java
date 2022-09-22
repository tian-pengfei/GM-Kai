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

public class TLCP11ProtocolMatcherTest {

    private final ProtocolMatcher protocolMatcher = new TLCP11ProtocolMatcher();

    private PreHandshakeContext preHandshakeContext;

    private HandshakeNegotiatorSession handshakeNegotiatorSession;


    // got data from old demo(git-number fcfad840) and wireshark to help test

    private static final byte[] client_hello_msg = Hexs.decode(
            "01 01 00 00 00 00 00 00 00 00 00 00\n" +
                    "   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00\n" +
                    "   00 00 00 00 00 00 00 00 04 e0 13 e0 11 01 00");

    private static final byte[] server_hello_msg = Hexs.decode("   01 01 00 00 00 00 00 00 00 00 00 00\n" +
            "   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00\n" +
            "   00 00 00 00 00 00 04 00 00 00 00 e0 13 00");

    @BeforeEach
    public void setup() {
        this.handshakeNegotiatorSession = mock(HandshakeNegotiatorSession.class);
        this.preHandshakeContext = mock(PreHandshakeContext.class);

        when(preHandshakeContext.getReusableSessionId()).thenReturn(null);

        when(preHandshakeContext.getSecureRandom()).thenReturn(new ZeroSecureRandom());

        when(preHandshakeContext.getSupportTLSCipherSuites()).
                thenReturn(Lists.newArrayList(TLSCipherSuite.ECC_SM4_CBC_SM3, TLSCipherSuite.ECDHE_SM4_CBC_SM3));

        when(preHandshakeContext.getSupportCompressionMethods()).
                thenReturn(Lists.newArrayList(CompressionMethod.NULL));
    }

    @Test
    public void should_create_client_hello() throws IOException {


        HandshakeMsg handshakeMsg =
                protocolMatcher.createClientHello(preHandshakeContext, handshakeNegotiatorSession);
        assertThat(handshakeMsg.getMsgBytes(), is(client_hello_msg));
    }

    @Test
    public void should_consume_client_hello() {

        boolean match = protocolMatcher.consumeClientHello(client_hello_msg, preHandshakeContext, handshakeNegotiatorSession);
        assertThat(match, is(true));
    }

    @Test
    public void should_create_server_hello() throws IOException {

        when(handshakeNegotiatorSession.getSessionId()).thenReturn(new byte[4]);
        when(handshakeNegotiatorSession.getCompressionMethod()).thenReturn(CompressionMethod.NULL);
        when(handshakeNegotiatorSession.getTlsCipherSuite()).thenReturn(TLSCipherSuite.ECC_SM4_CBC_SM3);
        HandshakeMsg handshakeMsg =
                protocolMatcher.createServerHello(preHandshakeContext, handshakeNegotiatorSession);

        assertThat(handshakeMsg.getMsgBytes(), is(server_hello_msg));

    }

    @Test
    public void should_consume_server_hello() {

        boolean match = protocolMatcher.consumeServerHello(server_hello_msg, preHandshakeContext, handshakeNegotiatorSession);

        assertThat(match, is(true));

    }

}
