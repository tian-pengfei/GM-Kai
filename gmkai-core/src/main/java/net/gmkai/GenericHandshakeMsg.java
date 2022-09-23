package net.gmkai;

import net.gmkai.util.ByteBuffers;

import javax.net.ssl.SSLException;
import java.io.IOException;
import java.nio.ByteBuffer;

public class GenericHandshakeMsg extends HandshakeMsg {

    private final HandshakeType handshakeType;

    private byte[] body;

    private GenericHandshakeMsg(HandshakeType handshakeType, byte[] body) {
        this.body = body;
        this.handshakeType = handshakeType;
    }

    @Override
    HandshakeType getHandshakeType() {
        return handshakeType;
    }

    @Override
    byte[] getBody() throws IOException {
        return body;
    }

    @Override
    int messageLength() {
        return body.length;
    }

    @Override
    void parse(ByteBuffer buffer) throws IOException {
        this.body = buffer.array();
    }

    public static GenericHandshakeMsg getInstance(byte[] handshakeMsg) throws IOException {

        ByteBuffer byteBuffer = ByteBuffer.wrap(handshakeMsg);
        HandshakeType handshakeType = HandshakeType.valueOf(byteBuffer.get()).
                orElseThrow(() -> new SSLException("unrecognized handshake type"));

        byte[] body = ByteBuffers.getBytes24(byteBuffer);

        return new GenericHandshakeMsg(handshakeType, body);
    }

}
