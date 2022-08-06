package com.tianpengfei.gmkai.application;

import com.tianpengfei.gmkai.TransportContext;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;

public class AppInputStream extends InputStream {

    private final TransportContext transportContext;

    private ByteBuffer buffer;

    private boolean appDataIsAvailable = false;//必须和buffer的读写状态同步

    public AppInputStream(TransportContext transportContext) {
        this.transportContext = transportContext;

        this.buffer = ByteBuffer.allocate(4096);
    }

    @Override
    public int read() throws IOException {
        byte[] b = new byte[1];
        int n = read(b, 0, 1);
        if (n <= 0) {
            return -1;
        }
        return b[0] & 0xFF;
    }

    @Override
    public int available() throws IOException {
        if (!appDataIsAvailable) {
            return -1;
        }
        return buffer.remaining();
    }

    @Override
    public synchronized int read(byte[] b, int off, int len)
            throws IOException {
        int availableLen = available();
        if (availableLen > 0) {

            len = Math.min(availableLen, len);
            buffer.get(b, off, len);
            return len;
        } else {
            appDataIsAvailable = false;
            buffer.clear();
        }
        ByteBuffer bb = transportContext.readApplicationRecord(buffer);

        if (bb == null) {
            return -1;
        } else {
            buffer = bb;
        }

        buffer.flip();
        len = Math.min(len, buffer.remaining());

        buffer.get(b, off, len);

        return len;
    }

    @Override
    public synchronized long skip(long n) throws IOException {
        byte[] skipArray = new byte[256];

        long skipped = 0;
        while (n > 0) {
            int len = (int) Math.min(n, skipArray.length);
            int r = read(skipArray, 0, len);
            if (r <= 0) {
                break;
            }
            n -= r;
            skipped += r;
        }

        return skipped;
    }

    @Override
    public void close() throws IOException {
        super.close();
        transportContext.closeRead();
    }


}
