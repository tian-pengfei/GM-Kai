package com.tianpengfei.gmkai.handshake;

import java.io.IOException;

public abstract class HandshakeMessage {

    HandshakeMessage() {
    }

    abstract SSLHandshakeType getHandshakeType();

    abstract byte[] getBytes() throws IOException;

    abstract int messageLength();

}
