package net.gmkai.util;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;

public interface Bytes {

    static byte[] concat(byte[]... arrays) {
        return com.google.common.primitives.Bytes.concat(arrays);
    }

    static byte[] safeRead(InputStream input, int len) throws IOException {
        byte[] buf = new byte[len];
        int count = 0;
        while (count < len) {
            int l = input.read(buf, count, len - count);
            if (l == -1) {
                throw new EOFException("unexpected end of stream");
            }
            count += l;
        }
        return buf;
    }
}
