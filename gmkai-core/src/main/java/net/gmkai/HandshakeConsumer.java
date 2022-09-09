package net.gmkai;

import java.io.IOException;

public interface HandshakeConsumer {

    void consume(HandshakeContext handshakeContext, byte[] message) throws IOException;

    void doAfterConsume(HandshakeContext handshakeContext);
}
