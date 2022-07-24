package com.tianpengfei.gmkai;

import com.tianpengfei.gmkai.handshake.HandshakeContext;
import com.tianpengfei.gmkai.record.ContentType;
import com.tianpengfei.gmkai.record.Plaintext;

import java.io.InputStream;
import java.io.OutputStream;

public class TransportContext implements ConnectionContext {

    TransportContextSpi transportContextSpi;

    HandshakeContext handshakeContext;

    void kickStart() {
        handshakeContext.kickstart(this);
    }

    GMSSLSession getSession() {
        return transportContextSpi.getSession();
    }

    GMSSLSession getHandshakeSession() {
        return transportContextSpi.getHandshakeSession();
    }

    InputStream getInputStream() {
        return transportContextSpi.getInputStream();
    }

    OutputStream getOutStream() {
        return transportContextSpi.getOutputStream();
    }

    public Plaintext readRecord() {

        return null;
    }

    public void writeRecord(ContentType contentType, byte[] message) {

    }
}
