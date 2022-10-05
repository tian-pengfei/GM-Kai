package net.gmkai;

import net.gmkai.event.TLSEventBus;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;

public class ApplicationDataService implements RecordUpperLayerProtocol {

    private final ApplicationMsgTransport applicationMsgTransport;

    private final TLSEventBus tlsEventBus;

    private final AppInputStream appInputStream = new AppInputStream();

    private final AppOutputStream appOutputStream = new AppOutputStream();

    public ApplicationDataService(TLSEventBus tlsEventBus, ApplicationMsgTransport applicationMsgTransport) {
        this.applicationMsgTransport = applicationMsgTransport;
        this.tlsEventBus = tlsEventBus;
    }

    public InputStream getAppInputStream() {
        return appInputStream;
    }

    public OutputStream getAppOutStream() {
        return appOutputStream;
    }

    @Override
    public void handleMsgFromOtherProtocol(TLSText tlsText) {
        //todo 1.3  0-RTT
        throw new RuntimeException();
    }


    private class AppInputStream extends InputStream {

        private ByteBuffer buffer;

        private boolean appDataIsAvailable = false;

        private AppInputStream() {
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

            if (b == null) {
                throw new NullPointerException();
            }

            int availableLen = available();
            if (availableLen > 0) {

                len = Math.min(availableLen, len);
                buffer.get(b, off, len);
                return len;
            } else {
                appDataIsAvailable = false;
                buffer.clear();
            }

            TLSText tlsText = applicationMsgTransport.readApplicationMsg();

            if (tlsText == null) {
                return -1;
            }

            if (buffer.remaining() < tlsText.fragment.length) {
                buffer = ByteBuffer.allocate(tlsText.fragment.length);
            }
            buffer.put(tlsText.fragment);

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
        }

    }

    private class AppOutputStream extends OutputStream {


        @Override
        public void write(int b) throws IOException {

            write((new byte[]{(byte) b}), 0, 1);
        }

        @Override
        public void write(byte[] b,
                          int off, int len) throws IOException {
            ByteBuffer appData = ByteBuffer.wrap(b, off, len);

            applicationMsgTransport.writeApplicationMsg(appData.array());
        }

        @Override
        public void close() throws IOException {
            super.close();
        }
    }


}
