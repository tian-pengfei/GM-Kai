package net.gmkai;


import net.gmkai.crypto.impl.bc.BcTLSCrypto;
import net.gmkai.util.Hexs;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class FinishedNodeTest {

    private HandshakeContext handshakeContext;

    private final byte[] masterSecret = Hexs.decode("2f22754c7c03f6401ffa7b8c746ba62008ed4c6dd09e4a3668415214f99970bcc9adb1f2dccd2b35eb449db3b5a8803e");

    private final byte[] client_finish_message = Hexs.decode("42329c34e5c1e558c214e551");

    private final byte[] server_finish_message = Hexs.decode("e81f9e1e224f58802ec2f0d6");

    private final byte[] client_finish_hash =
            Hexs.decode("e623f473641b514b2050a6b18a47eb595874726dc74a881b726beb4c59ac5b6d");

    private final byte[] server_finish_hash =
            Hexs.decode("494620b9ddc80cc2e0be01655e90d645297c80ec184313363e789b607901d7c3");


    @BeforeEach
    public void setUp() throws Exception {
        this.handshakeContext = mock(HandshakeContext.class);
        when(handshakeContext.getTLSCrypto()).thenReturn(new BcTLSCrypto());
    }

    @Test
    public void should_product_client_finish_message() throws IOException {
        should_product_finish_message(true, client_finish_hash, client_finish_message);
    }


    @Test
    public void should_consume_client_finish_message() throws IOException {
        should_consume_finish_message(false, client_finish_hash, client_finish_message);
    }

    @Test
    public void should_product_server_finish_message() throws IOException {
        should_product_finish_message(false, server_finish_hash, server_finish_message);
    }


    @Test
    public void should_consume_server_finish_message() throws IOException {
        should_consume_finish_message(true, server_finish_hash, server_finish_message);
    }

    private void should_product_finish_message(boolean isClient, byte[] hash, byte[] expectedMessage) throws IOException {

        FinishedNode finishedNode = new FinishedNode(handshakeContext -> false);
        when(handshakeContext.getMasterSecret()).thenReturn(masterSecret);
        when(handshakeContext.getHandshakeHash()).thenReturn(hash);
        when(handshakeContext.isClientMode()).thenReturn(isClient);
        HandshakeMsg handshakeMsg = finishedNode.doProduce(handshakeContext);
        assertThat(handshakeMsg.getBody(), is(expectedMessage));

    }

    private void should_consume_finish_message(boolean isClient, byte[] hash, byte[] message) throws IOException {
        FinishedNode finishedNode = new FinishedNode(handshakeContext -> true);
        when(handshakeContext.getMasterSecret()).thenReturn(masterSecret);
        when(handshakeContext.getHandshakeHash()).thenReturn(hash);
        when(handshakeContext.isClientMode()).thenReturn(isClient);
        finishedNode.doConsume(handshakeContext, message);
    }


}
