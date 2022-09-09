package net.gmkai;

import net.gmkai.util.ByteBufferBuilder;

import javax.net.ssl.SSLException;
import java.io.IOException;
import java.nio.ByteBuffer;

import static net.gmkai.util.BufferWriteOperations.put;
import static net.gmkai.util.BufferWriteOperations.putBytes24;

public abstract class HandshakeMsg {

    HandshakeMsg() {
    }

    HandshakeMsg(byte[] message) throws IOException {
        checkMessageLength(message);
        parse(ByteBuffer.wrap(message));
    }

    abstract HandshakeType getHandshakeType();

    public byte[] getProtocolFormat() throws IOException {

        return ByteBufferBuilder.
                bufferCapacity(1 + 3 + messageLength()).
                operate(put(getHandshakeType().id)).
                operate(putBytes24(getMsgBytes())).buildByteArray();

    }

    abstract byte[] getMsgBytes() throws IOException;

    abstract int messageLength();

    void checkMessageLength(byte[] message) throws SSLException {
        if (message == null)
            throw new SSLException("HandshakeMsg length is expected");
    }

    abstract void parse(ByteBuffer buffer) throws IOException;

}
