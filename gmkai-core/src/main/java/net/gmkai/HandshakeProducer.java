package net.gmkai;

import javax.net.ssl.SSLException;

public interface HandshakeProducer {

    HandshakeMsg produce(HandshakeContext handshakeContext) throws SSLException;

    void doAfterProduce(HandshakeContext handshakeContext);

}
