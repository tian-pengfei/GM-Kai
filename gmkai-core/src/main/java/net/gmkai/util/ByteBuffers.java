package net.gmkai.util;

import javax.net.ssl.SSLException;
import java.io.IOException;
import java.nio.ByteBuffer;

public interface ByteBuffers {

    static int getInt8(ByteBuffer m) throws IOException {
        verifyLength(m, 1);
        return (m.get() & 0xFF);
    }

    static int getInt16(ByteBuffer m) throws IOException {
        verifyLength(m, 2);
        return ((m.get() & 0xFF) << 8) |
                (m.get() & 0xFF);
    }

    static int getInt24(ByteBuffer m) throws IOException {
        verifyLength(m, 3);
        return ((m.get() & 0xFF) << 16) |
                ((m.get() & 0xFF) << 8) |
                (m.get() & 0xFF);
    }

    static int getInt32(ByteBuffer m) throws IOException {
        verifyLength(m, 4);
        return ((m.get() & 0xFF) << 24) |
                ((m.get() & 0xFF) << 16) |
                ((m.get() & 0xFF) << 8) |
                (m.get() & 0xFF);
    }


    /*
     * Read byte vectors with 8, 16, and 24 bit length encodings.
     */
    static byte[] getBytes8(ByteBuffer m) throws IOException {
        int len = getInt8(m);
        verifyLength(m, len);
        byte[] b = new byte[len];

        m.get(b);
        return b;
    }

    static byte[] getBytes16(ByteBuffer m) throws IOException {
        int len = getInt16(m);
        verifyLength(m, len);
        byte[] b = new byte[len];

        m.get(b);
        return b;
    }

    static byte[] getBytes(ByteBuffer m, int len) throws IOException {
        verifyLength(m, len);
        byte[] b = new byte[len];
        m.get(b);
        return b;
    }

    static byte[] getBytes24(ByteBuffer m) throws IOException {
        int len = getInt24(m);
        verifyLength(m, len);
        byte[] b = new byte[len];

        m.get(b);
        return b;
    }

    /*
     * Write 8, 16, 24, and 32 bit integer data types, encoded
     * in standard big-endian form.
     */
    static void putInt8(ByteBuffer m, int i) throws IOException {
        verifyLength(m, 1);
        m.put((byte) (i & 0xFF));
    }

    static void putInt16(ByteBuffer m, int i) throws IOException {
        verifyLength(m, 2);
        m.put((byte) ((i >> 8) & 0xFF));
        m.put((byte) (i & 0xFF));
    }

    static void putInt24(ByteBuffer m, int i) throws IOException {
        verifyLength(m, 3);
        m.put((byte) ((i >> 16) & 0xFF));
        m.put((byte) ((i >> 8) & 0xFF));
        m.put((byte) (i & 0xFF));
    }

    static void putInt32(ByteBuffer m, int i) throws IOException {
        verifyLength(m, 4);
        m.put((byte) ((i >> 24) & 0xFF));
        m.put((byte) ((i >> 16) & 0xFF));
        m.put((byte) ((i >> 8) & 0xFF));
        m.put((byte) (i & 0xFF));
    }

    /*
     * Write byte vectors with 8, 16, and 24 bit length encodings.
     */
    static void putBytes8(ByteBuffer m, byte[] s) throws IOException {
        if (s == null || s.length == 0) {
            verifyLength(m, 1);
            putInt8(m, 0);
        } else {
            verifyLength(m, 1 + s.length);
            putInt8(m, s.length);
            m.put(s);
        }
    }

    static void putBytes16(ByteBuffer m, byte[] s) throws IOException {
        if (s == null || s.length == 0) {
            verifyLength(m, 2);
            putInt16(m, 0);
        } else {
            verifyLength(m, 2 + s.length);
            putInt16(m, s.length);
            m.put(s);
        }
    }

    static void putBytes24(ByteBuffer m, byte[] s) throws IOException {
        if (s == null || s.length == 0) {
            verifyLength(m, 3);
            putInt24(m, 0);
        } else {
            verifyLength(m, 3 + s.length);
            putInt24(m, s.length);
            m.put(s);
        }
    }

    static void putBytes(ByteBuffer m, byte[]... bytesArray) throws IOException {
        for (byte[] bytes : bytesArray) {
            m.put(bytes, 0, bytes.length);
        }
    }

    // Verify that the buffer has sufficient remaining.
    static void verifyLength(
            ByteBuffer m, int len) throws SSLException {
        if (len > m.remaining()) {
            throw new SSLException("Insufficient space in the buffer, " +
                    "may be cause by an unexpected end of handshake data.");
        }
    }


    static void putLong64(ByteBuffer m, long i) throws IOException {
        verifyLength(m, 8);
        m.put((byte) ((i >> 56) & 0xFF));
        m.put((byte) ((i >> 48) & 0xFF));
        m.put((byte) ((i >> 40) & 0xFF));
        m.put((byte) ((i >> 32) & 0xFF));
        m.put((byte) ((i >> 24) & 0xFF));
        m.put((byte) ((i >> 16) & 0xFF));
        m.put((byte) ((i >> 8) & 0xFF));
        m.put((byte) (i & 0xFF));
    }
}
