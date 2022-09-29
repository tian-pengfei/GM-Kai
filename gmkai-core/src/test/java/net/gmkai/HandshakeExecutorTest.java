package net.gmkai;

import com.google.common.collect.ImmutableList;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLException;
import java.io.IOException;
import java.nio.ByteBuffer;

import static net.gmkai.HandshakeExecutor.*;
import static net.gmkai.HandshakeType.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class HandshakeExecutorTest {


    private HandshakeExecutor handshakeExecutor;


    @BeforeEach
    public void setUp() throws IOException {

        HandshakeContext handshakeContext = mock(HandshakeContext.class);
        HandshakeMsgTransport handshakeMsgTransport = mock(HandshakeMsgTransport.class);

        when(handshakeMsgTransport.readHandshakeMsg()).thenReturn(
                new DummyMsg(CERTIFICATE),
                new DummyMsg(SERVER_KEY_EXCHANGE),
                new DummyMsg(SERVER_HELLO_DONE),
                new DummyMsg(FINISHED)).thenThrow(new SSLException("transport already closed"));

        handshakeExecutor = new HandshakeExecutor(handshakeMsgTransport, handshakeContext);
    }

    @Test
    public void should_execute() throws IOException {
        HandshakeNodes handshakeNodes = new HandshakeNodes(ImmutableList.of(
                new DummyNode(CERTIFICATE, true, false),
                new DummyNode(SERVER_KEY_EXCHANGE, true, false),
                new DummyNode(CERTIFICATE_REQUEST, true, true),
                new DummyNode(SERVER_HELLO_DONE, true, false),
                new DummyNode(CERTIFICATE, false, false),
                new DummyNode(CLIENT_KEY_EXCHANGE, false, false),
                new DummyNode(CERTIFICATE_VERIFY, false, false),
                new DummyNode(FINISHED, false, false),
                new DummyNode(FINISHED, true, false)
        ), 123L);

        handshakeExecutor.execute(handshakeNodes);
    }

    @Test
    public void should_throw_exception_for_wrong_type_consume_node() {
        HandshakeNodes handshakeNodes = new HandshakeNodes(ImmutableList.of(
                new DummyNode(CERTIFICATE, true, false),
                new DummyNode(SERVER_KEY_EXCHANGE, true, false),
                new DummyNode(CERTIFICATE_REQUEST, true, false),//wrong
                new DummyNode(SERVER_HELLO_DONE, true, false),
                new DummyNode(CERTIFICATE, false, true),
                new DummyNode(CLIENT_KEY_EXCHANGE, false, false),
                new DummyNode(CERTIFICATE_VERIFY, false, false),
                new DummyNode(FINISHED, false, false),
                new DummyNode(FINISHED, true, false)
        ), 123L);

        Throwable exception = Assertions.assertThrowsExactly(SSLException.class,
                () -> handshakeExecutor.execute(handshakeNodes));
        Assertions.assertEquals(WRONG_TYPE_NODE, exception.getMessage());
    }

    @Test
    public void should_throw_exception_for_not_found_produce_node_before_consume() {
        HandshakeNodes handshakeNodes = new HandshakeNodes(ImmutableList.of(
                new DummyNode(CERTIFICATE, true, false),
                new DummyNode(SERVER_KEY_EXCHANGE, true, false),
                new DummyNode(CERTIFICATE_REQUEST, true, true),
                new DummyNode(SERVER_HELLO_DONE, true, false),
                new DummyNode(CERTIFICATE, false, false),
                new DummyNode(CLIENT_KEY_EXCHANGE, false, false),
                new DummyNode(CERTIFICATE_VERIFY, false, false),
                new DummyNode(FINISHED, false, true),//wrong
                new DummyNode(FINISHED, true, false)
        ), 123L);

        Throwable exception = Assertions.assertThrowsExactly(SSLException.class,
                () -> handshakeExecutor.execute(handshakeNodes));
        Assertions.assertEquals(NOT_FOUND_PRODUCE_NODE, exception.getMessage());
    }

    @Test
    public void should_throw_exception_for_not_found_consume_node_before_produce() {
        HandshakeNodes handshakeNodes = new HandshakeNodes(ImmutableList.of(
                new DummyNode(CERTIFICATE, true, false),
                new DummyNode(SERVER_KEY_EXCHANGE, true, false),
                new DummyNode(CERTIFICATE_REQUEST, true, true),
//                new DummyNode(SERVER_HELLO_DONE,true,false), wrong
                new DummyNode(CERTIFICATE, false, true),
                new DummyNode(CLIENT_KEY_EXCHANGE, false, false),
                new DummyNode(CERTIFICATE_VERIFY, false, false),
                new DummyNode(FINISHED, false, false),
                new DummyNode(FINISHED, true, false)
        ), 123L);

        Throwable exception = Assertions.assertThrowsExactly(SSLException.class,
                () -> handshakeExecutor.execute(handshakeNodes));
        Assertions.assertEquals(NOT_FOUND_CONSUME_NODE, exception.getMessage());
    }

    @Test
    public void should_throw_exception_for_not_found_consume_node_before_finished() {
        HandshakeNodes handshakeNodes = new HandshakeNodes(ImmutableList.of(
                new DummyNode(CERTIFICATE, true, false),
                new DummyNode(SERVER_KEY_EXCHANGE, true, false),
                new DummyNode(CERTIFICATE_REQUEST, true, true),
                new DummyNode(SERVER_HELLO_DONE, true, false),
                new DummyNode(CERTIFICATE, false, true),
                new DummyNode(CLIENT_KEY_EXCHANGE, false, false),
                new DummyNode(CERTIFICATE_VERIFY, false, false),
                new DummyNode(FINISHED, false, false),
                new DummyNode(CERTIFICATE_REQUEST, true, true)//wrong
        ), 123L);

        Throwable exception = Assertions.assertThrowsExactly(SSLException.class,
                () -> handshakeExecutor.execute(handshakeNodes));
        Assertions.assertEquals(NOT_FOUND_CONSUME_NODE, exception.getMessage());
    }

    @Test
    public void should_throw_exception_for_not_found_produce_node_before_finished() {
        HandshakeNodes handshakeNodes = new HandshakeNodes(ImmutableList.of(
                new DummyNode(CERTIFICATE, false, true)
        ), 123L);

        Throwable exception = Assertions.assertThrowsExactly(SSLException.class,
                () -> handshakeExecutor.execute(handshakeNodes));
        Assertions.assertEquals(NOT_FOUND_PRODUCE_NODE, exception.getMessage());
    }


    private static class DummyMsg extends HandshakeMsg {

        private final HandshakeType handshakeType;

        public DummyMsg(HandshakeType handshakeType) {
            this.handshakeType = handshakeType;
        }

        @Override
        HandshakeType getHandshakeType() {
            return handshakeType;
        }

        @Override
        byte[] getBody() throws IOException {
            return new byte[0];
        }

        @Override
        int messageLength() {
            return 0;
        }

        @Override
        void parse(ByteBuffer buffer) throws IOException {

        }
    }


    private static class DummyNode extends HandshakeNode {

        private final boolean consumable;

        private final HandshakeType handshakeType;

        private final boolean optional;

        public DummyNode(HandshakeType handshakeType, boolean consumable, boolean optional) {
            this.consumable = consumable;
            this.handshakeType = handshakeType;
            this.optional = optional;
        }

        @Override
        public boolean consumable(HandshakeContext handshakeContext) {
            return consumable;
        }

        @Override
        public void doAfterConsume(HandshakeContext handshakeContext) throws SSLException {

        }

        @Override
        protected void doConsume(HandshakeContext handshakeContext, byte[] message) throws IOException {

        }

        @Override
        protected HandshakeMsg doProduce(HandshakeContext handshakeContext) throws IOException {
            return new DummyMsg(handshakeType);
        }


        @Override
        public HandshakeType getHandshakeType() {
            return handshakeType;
        }

        @Override
        public boolean optional(HandshakeContext handshakeContext) {
            return optional;
        }

        @Override
        public void doAfterProduce(HandshakeContext handshakeContext) throws SSLException {
        }
    }

}
