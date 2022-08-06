package com.tianpengfei.gmkai.handshake;

import java.io.IOException;
import java.nio.ByteBuffer;

public class ServerHelloDone {

    static final SSLHandshakeType TYPE = SSLHandshakeType.SERVER_HELLO_DONE;

    static final HandshakeProducer handshakeProducer = new ServerHelloDoneProducer();

    static final HandshakeConsumer handshakeConsumer = new ServerHelloDoneConsumer();


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

    static class ServerHelloDoneConsumer implements HandshakeConsumer {

        @Override
        public void consume(HandshakeContext handshakeContext, ByteBuffer message) throws IOException {

            handshakeContext.switch2write();
        }

        @Override
        public SSLHandshakeType handshakeType() {
            return TYPE;
        }


    }

    static class ServerHelloDoneProducer implements HandshakeProducer {

        @Override
        public HandshakeMessage produce(HandshakeContext handshakeContext) {


            return new ServerHelloDoneMessage();
        }

        @Override
        public void finished(HandshakeContext handshakeContext) {
            handshakeContext.switch2read();
        }
    }

}
