package com.tianpengfei.gmkai;

import java.nio.ByteBuffer;

public class HandshakeNode implements HandshakeConsumer,HandshakeProducer{

    private final HandshakeConsumer handshakeConsumer;

    private final HandshakeProducer handshakeProducer;

    public HandshakeNode(HandshakeConsumer handshakeConsumer, HandshakeProducer handshakeProducer) {
        this.handshakeConsumer = handshakeConsumer;
        this.handshakeProducer = handshakeProducer;
    }

    @Override
    public void consume(HandshakeContext handshakeContext, ByteBuffer byteBuffer) {
        this.handshakeConsumer.consume(handshakeContext,byteBuffer);
    }

    @Override
    public void product(HandshakeContext handshakeContext) {
        this.handshakeProducer.product(handshakeContext);
    }
}
