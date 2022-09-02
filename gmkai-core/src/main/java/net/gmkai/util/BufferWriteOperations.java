package net.gmkai.util;

import java.io.IOException;

public interface BufferWriteOperations {

    static ByteBufferOperation putInt8(int i) {
        return m -> ByteBuffers.putInt8(m, i);
    }

    static ByteBufferOperation putInt16(int i) throws IOException {
        return m -> ByteBuffers.putInt16(m, i);
    }

    static ByteBufferOperation putInt24(int i) throws IOException {
        return m -> ByteBuffers.putInt24(m, i);
    }

    static ByteBufferOperation putInt32(int i) throws IOException {
        return m -> ByteBuffers.putInt32(m, i);
    }


    static ByteBufferOperation putBytes8(byte[] s) throws IOException {
        return m -> ByteBuffers.putBytes8(m, s);
    }

    static ByteBufferOperation putBytes16(byte[] s) throws IOException {
        return m -> ByteBuffers.putBytes16(m, s);
    }

    static ByteBufferOperation putBytes24(byte[] s) throws IOException {
        return m -> ByteBuffers.putBytes24(m, s);
    }

    static ByteBufferOperation putBytes(byte[]... bytesArray) throws IOException {
        return m -> ByteBuffers.putBytes(m, bytesArray);
    }

    static ByteBufferOperation putLong64(long i) throws IOException {
        return m -> ByteBuffers.putLong64(m, i);
    }

    static ByteBufferOperation put(byte b) throws IOException {
        return m -> m.put(b);
    }
}
