package net.gmkai;

import com.google.common.collect.Lists;
import net.gmkai.util.Hexs;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import test.ZeroSecureRandom;

import java.io.IOException;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.any;
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

    private static final byte[] server_hello_msg = Hexs.decode(
            "   01 01 00 00 00 00 00 00 00 00 00 00\n" +
                    "   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00\n" +
                    "   00 00 00 00 00 00 04 00 00 00 00 e0 13 00");

    private static final byte[] tls12_client_hello_msg = Hexs.decode(
            "      03 03 f0 e6 f0 8c 18 1f 64 3e a4 e9\n" +
                    "   20 42 c0 55 a4 ba d2 d1 a8 d7 e9 af 6e 2c 58 ca\n" +
                    "   22 b8 0f dc 31 70 00 00 20 c0 2f c0 2b c0 30 c0\n" +
                    "   2c 00 9e 00 a2 00 a3 00 9f c0 27 c0 23 c0 28 c0\n" +
                    "   24 00 67 00 40 00 6b 00 ff 01 00 00 6e 00 00 00\n" +
                    "   15 00 13 00 00 10 67 72 61 70 68 2e 6f 63 75 6c\n" +
                    "   75 73 2e 63 6f 6d 00 0b 00 04 03 00 01 02 00 0a\n" +
                    "   00 0a 00 08 00 1d 00 17 00 19 00 18 33 74 00 00\n" +
                    "   00 10 00 0b 00 09 08 68 74 74 70 2f 31 2e 31 00\n" +
                    "   16 00 00 00 17 00 00 00 0d 00 20 00 1e 06 01 06\n" +
                    "   02 06 03 05 01 05 02 05 03 04 01 04 02 04 03 03\n" +
                    "   01 03 02 03 03 02 01 02 02 02 03");

    private static final byte[] tls12_server_hello_msg = Hexs.decode(
            "  03 03 88 ff 6b 58 a6 eb 1f b5 dc 08\n" +
                    "   70 34 68 45 76 88 1a eb 4a 89 67 9a e8 1f 30 64\n" +
                    "   fb b2 10 39 6c 55 20 4c 68 ba 09 11 c3 9d 46 ae\n" +
                    "   ed b2 ac 4f 1d c7 8c 0a d8 71 16 c5 da e1 8a 4a\n" +
                    "   5a 40 f0 6e 47 7d 0c c0 2f 00 00 24 ff 01 00 01\n" +
                    "   00 00 00 00 00 00 0b 00 04 03 00 01 02 00 10 00\n" +
                    "   0b 00 09 08 68 74 74 70 2f 31 2e 31 00 17 00 00");

    private static final GMKaiExtendedSSLSession sslSession = new GMKaiSSLSession(
            new byte[]{0, 0, 0, 0},
            "0.0.0.0",
            -1,
            TLSCipherSuite.ECC_SM4_CBC_SM3,
            CompressionMethod.NULL
    );

    @BeforeEach
    public void setup() {
        this.handshakeNegotiatorSession = mock(HandshakeNegotiatorSession.class);
        this.preHandshakeContext = mock(PreHandshakeContext.class);

        when(preHandshakeContext.getClientReusableSessionId()).thenReturn(null);

        when(preHandshakeContext.getSessionById(any())).thenReturn(null);

        when(preHandshakeContext.getSecureRandom()).thenReturn(new ZeroSecureRandom());

        when(preHandshakeContext.getSupportTLSCipherSuites()).
                thenReturn(Lists.newArrayList(TLSCipherSuite.ECC_SM4_CBC_SM3, TLSCipherSuite.ECDHE_SM4_CBC_SM3));

        when(preHandshakeContext.getSupportCompressionMethods()).
                thenReturn(Lists.newArrayList(CompressionMethod.NULL));

        when(preHandshakeContext.createSSLSession(any(), any(), any())).thenReturn(sslSession);

    }

    @Test
    public void should_create_client_hello() throws IOException {


        HandshakeMsg handshakeMsg =
                protocolMatcher.createClientHello(preHandshakeContext, handshakeNegotiatorSession);
        assertThat(handshakeMsg.getBody(), is(client_hello_msg));
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

        assertThat(handshakeMsg.getBody(), is(server_hello_msg));

    }

    @Test
    public void should_consume_server_hello() {

        boolean match = protocolMatcher.consumeServerHello(server_hello_msg, preHandshakeContext, handshakeNegotiatorSession);

        assertThat(match, is(true));

    }

    @Test
    public void should_not_match_tls12_client_hello() {

        boolean match = protocolMatcher.consumeClientHello(tls12_client_hello_msg, preHandshakeContext, handshakeNegotiatorSession);
        assertThat(match, is(false));
    }

    @Test
    public void should_not_match_tls12_server_hello() {

        boolean match = protocolMatcher.consumeServerHello(tls12_server_hello_msg, preHandshakeContext, handshakeNegotiatorSession);

        assertThat(match, is(false));

    }


}
