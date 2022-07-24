package com.tianpengfei.gmkai.application;

import com.tianpengfei.gmkai.record.RecordOutputStream;

import java.io.IOException;
import java.io.OutputStream;

public class AppOutputStream extends OutputStream {

    private RecordOutputStream outputStream;

    public AppOutputStream(RecordOutputStream outputStream) {
        this.outputStream = outputStream;
    }

    @Override
    public void write(int b) throws IOException {

    }

    @Override
    public void write(byte[] b,
                      int off, int len) throws IOException {

    }

    @Override
    public void close() throws IOException {

    }

}
