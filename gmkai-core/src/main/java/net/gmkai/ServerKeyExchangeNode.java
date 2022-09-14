package net.gmkai;

public abstract class ServerKeyExchangeNode extends HandshakeNode {

    @Override
    public final boolean consumable(HandshakeContext handshakeContext) {
        return handshakeContext.isClientMode();
    }

    @Override
    public void doAfterConsume(HandshakeContext handshakeContext) {

    }

    @Override
    public final boolean optional(HandshakeContext handshakeContext) {
        return false;
    }

    @Override
    public void doAfterProduce(HandshakeContext handshakeContext) {

    }


}
