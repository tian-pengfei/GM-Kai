package com.tianpengfei.gmkai.handshake;

import com.tianpengfei.gmkai.SSLProducer;

public interface HandshakeProducer extends SSLProducer<HandshakeContext, HandshakeMessage> {

    default boolean isNeed(HandshakeContext context) {
        return true;
    }

    default void finished(HandshakeContext handshakeContext) {
    }
}
