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

}
