package net.gmkai;

import java.io.IOException;
import java.nio.ByteBuffer;

public class ServerHelloDoneNode extends HandshakeNode {

    @Override
    public boolean consumable(HandshakeContext handshakeContext) {
        return handshakeContext.isClientMode();
    }

    @Override
    public void doAfterConsume(HandshakeContext handshakeContext) {

    }

    @Override
    protected void doConsume(HandshakeContext handshakeContext, byte[] message) throws IOException {

    }

    @Override
    protected HandshakeMsg doProduce(HandshakeContext handshakeContext) throws IOException {
        return new ServerHelloDoneMsg();
    }

    @Override
    public HandshakeType getHandshakeType() {
        return HandshakeType.SERVER_HELLO_DONE;
    }

    @Override
    public boolean optional(HandshakeContext handshakeContext) {
        return false;
    }

    @Override
    public void doAfterProduce(HandshakeContext handshakeContext) {

    }

    static class ServerHelloDoneMsg extends HandshakeMsg {


        @Override
        HandshakeType getHandshakeType() {
            return HandshakeType.SERVER_HELLO_DONE;
        }

        @Override
        byte[] getBody() throws IOException {
            return new byte[0];
        }

        @Override
        int messageLength() {
            return 0;
        }

        @Override
        void parse(ByteBuffer buffer) throws IOException {
        }

    }
}
