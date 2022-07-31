package com.tianpengfei.gmkai.handshake;

import java.io.IOException;
import java.nio.ByteBuffer;

public class ServerHelloDone {

    static final SSLHandshakeType TYPE = SSLHandshakeType.SERVER_HELLO_DONE;

    static class ServerHelloDoneMessage extends HandshakeMessage {


        @Override
        SSLHandshakeType getHandshakeType() {
            return TYPE;
        }

        @Override
        byte[] getBytes() throws IOException {
            return new byte[0];
        }

        @Override
        int messageLength() {
            return 0;
        }
    }

    static class ServerHelloConsumer implements HandshakeConsumer {

        @Override
        public void consume(HandshakeContext handshakeContext, ByteBuffer message) throws IOException {

            handshakeContext.readFinished();
        }

        @Override
        public SSLHandshakeType handshakeType() {
            return TYPE;
        }


    }

    static class ServerHelloProducer implements HandshakeProducer {

        @Override
        public HandshakeMessage produce(HandshakeContext handshakeContext) {

            handshakeContext.writeFinished();
            return new ServerHelloDoneMessage();
        }

    }

}
