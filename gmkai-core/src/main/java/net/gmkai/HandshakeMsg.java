package net.gmkai;

import net.gmkai.util.ByteBufferBuilder;
import net.gmkai.util.ByteBuffers;

import javax.net.ssl.SSLException;
import java.io.IOException;
import java.nio.ByteBuffer;

import static net.gmkai.util.BufferWriteOperations.put;
import static net.gmkai.util.BufferWriteOperations.putBytes24;

public abstract class HandshakeMsg {

    HandshakeMsg() {
    }

    HandshakeMsg(ByteBuffer buffer) throws IOException {
        checkMessageLength(buffer);
        parse(buffer);
    }

    abstract HandshakeType getHandshakeType();

    public byte[] getMsg() throws IOException {

        return ByteBufferBuilder.
                bufferCapacity(1 + 3 + messageLength()).
                operate(put(getHandshakeType().id)).
                operate(putBytes24(getBody())).buildByteArray();

    }

    abstract byte[] getBody() throws IOException;

    abstract int messageLength();

    void checkMessageLength(ByteBuffer buffer) throws SSLException {
        if (buffer == null)
            throw new SSLException("HandshakeMsg length is expected");
    }

    abstract void parse(ByteBuffer buffer) throws IOException;

    public static HandshakeMsg getInstance(byte[] handshakeMsg) throws IOException {

        ByteBuffer byteBuffer = ByteBuffer.wrap(handshakeMsg);
        HandshakeType handshakeType = HandshakeType.valueOf(byteBuffer.get()).
                orElseThrow(() -> new SSLException("unrecognized handshake type"));

        byte[] body = ByteBuffers.getBytes24(byteBuffer);

        return new GenericHandshakeMsg(handshakeType, body);
    }


    static private class GenericHandshakeMsg extends HandshakeMsg {

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
    }


}
