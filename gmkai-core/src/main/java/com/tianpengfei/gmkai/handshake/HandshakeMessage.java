package com.tianpengfei.gmkai.handshake;

import java.io.IOException;

public abstract class HandshakeMessage {

    HandshakeMessage(byte[] message) {
        parse(message);
    }

    HandshakeMessage() {
    }

    abstract byte[] getHandshakeType();

    abstract byte[] getBytes() throws IOException;

    abstract void parse(byte[] messages);

    abstract int messageLength();

}
