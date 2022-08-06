package com.tianpengfei.gmkai;

import javax.net.ssl.SSLSessionContext;
import java.util.Enumeration;

public class GMSSLSessionContext implements SSLSessionContext {


    @Override
    public GMSSLSession getSession(byte[] sessionId) {
        return null;
    }

    @Override
    public Enumeration<byte[]> getIds() {
        return null;
    }

    @Override
    public void setSessionTimeout(int seconds) throws IllegalArgumentException {

    }

    @Override
    public int getSessionTimeout() {
        return 0;
    }

    @Override
    public void setSessionCacheSize(int size) throws IllegalArgumentException {

    }

    @Override
    public int getSessionCacheSize() {
        return 0;
    }
}
