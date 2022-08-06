package com.tianpengfei.gmkai.handshake;

import com.tianpengfei.gmkai.SSLConsumer;

import java.nio.ByteBuffer;

public interface HandshakeConsumer extends SSLConsumer<HandshakeContext, ByteBuffer> {


    default boolean isNeed(HandshakeContext handshakeContext) {
        return true;
    }

    SSLHandshakeType handshakeType();
}
