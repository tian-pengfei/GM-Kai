package com.tianpengfei.gmkai.application;

import com.tianpengfei.gmkai.TransportContext;

import java.io.IOException;

import java.io.OutputStream;

public class AppOutputStream extends OutputStream {

    private final TransportContext transportContext;

    public AppOutputStream(TransportContext transportContext) {
        this.transportContext = transportContext;
    }

    @Override
    public void write(int b) throws IOException {

        write((new byte[]{(byte) b}), 0, 1);
    }

    @Override
    public void write(byte[] b,
                      int off, int len) throws IOException {

        transportContext.startHandshake();

        transportContext.writeApplicationRecord(b, off, len);


    }

    @Override
    public void close() throws IOException {
        super.close();
        transportContext.closeWrite();
    }

}
