package com.tianpengfei.gmkai;

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;

public class TransportContext implements ConnectionContext{


    void dispatch(ByteBuffer message) {

    }

    void kickStart() {

    }

    GMSSLSession getSession() {
        return null;
    }

    GMSSLSession getHandshakeSession() {
        return null;
    }

    InputStream getInputStream() {
        return null;
    }

    OutputStream getOutStream() {
        return null;
    }
}
