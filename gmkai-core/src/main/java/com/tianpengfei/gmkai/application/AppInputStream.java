package com.tianpengfei.gmkai.application;

import com.tianpengfei.gmkai.record.RecordInputStream;

import java.io.IOException;
import java.io.InputStream;

public class AppInputStream extends InputStream {

    private RecordInputStream inputStream;

    public AppInputStream(RecordInputStream inputStream) {
        this.inputStream = inputStream;
    }

    @Override
    public int read() throws IOException {
        return 0;
    }

    @Override
    public int available() throws IOException {
        return 0;
    }

    @Override
    public int read(byte[] b, int off, int len)
            throws IOException {
        return 0;
    }

    @Override
    public synchronized long skip(long n) throws IOException {
        return 0;
    }

    @Override
    public void close() throws IOException {

    }
}
