package net.gmkai;

import javax.net.ssl.SSLException;
import java.io.IOException;

public interface HandshakeConsumer {

    void consume(HandshakeContext handshakeContext, byte[] message) throws IOException;

    void doAfterConsume(HandshakeContext handshakeContext) throws SSLException;
}
