package net.gmkai;

import javax.net.ssl.SSLException;
import java.io.IOException;

public abstract class HandshakeNode implements HandshakeProducer, HandshakeConsumer, HandshakeConsumable, HandshakeOptional {


    @Override
    final public void consume(HandshakeContext handshakeContext, byte[] message) throws IOException {
        if (optional(handshakeContext) || !consumable(handshakeContext)) {
            throw new SSLException("");
        }
        doConsume(handshakeContext, message);
    }

    @Override
    final public HandshakeMsg produce(HandshakeContext handshakeContext) throws IOException {
        if (optional(handshakeContext) || consumable(handshakeContext)) throw new SSLException("");
        return doProduce(handshakeContext);
    }

    protected abstract void doConsume(HandshakeContext handshakeContext, byte[] message) throws IOException;

    protected abstract HandshakeMsg doProduce(HandshakeContext handshakeContext) throws IOException;

    public abstract HandshakeType getHandshakeType();

    public final void doAfter(HandshakeContext handshakeContext) throws SSLException {
        if (consumable(handshakeContext)) {
            doAfterConsume(handshakeContext);
            return;
        }

        doAfterProduce(handshakeContext);
    }
}
