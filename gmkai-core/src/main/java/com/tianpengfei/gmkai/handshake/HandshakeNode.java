package com.tianpengfei.gmkai.handshake;

import java.io.IOException;
import java.nio.ByteBuffer;

public class HandshakeNode implements HandshakeConsumer, HandshakeProducer {

    private final HandshakeConsumer handshakeConsumer;

    private final HandshakeProducer handshakeProducer;

    public HandshakeNode(HandshakeConsumer handshakeConsumer, HandshakeProducer handshakeProducer) {
        this.handshakeConsumer = handshakeConsumer;
        this.handshakeProducer = handshakeProducer;
    }

    @Override
    public void consume(HandshakeContext handshakeContext, ByteBuffer byteBuffer) throws IOException {
        this.handshakeConsumer.consume(handshakeContext, byteBuffer);
    }

    @Override
    public HandshakeMessage produce(HandshakeContext handshakeContext) throws IOException {
        return this.handshakeProducer.produce(handshakeContext);
    }


    @Override
    public boolean isNeed(HandshakeContext context) {
        return true;
    }

    @Override
    public SSLHandshakeType handshakeType() {
        return null;
    }
}
