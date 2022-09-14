package net.gmkai;

import javax.net.ssl.SSLException;
import java.io.IOException;

public interface HandshakeProducer {

    HandshakeMsg produce(HandshakeContext handshakeContext) throws IOException;

    void doAfterProduce(HandshakeContext handshakeContext);

}
