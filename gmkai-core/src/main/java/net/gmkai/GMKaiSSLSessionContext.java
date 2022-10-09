package net.gmkai;

import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionContext;
import java.util.Enumeration;

//todo
public class GMKaiSSLSessionContext implements SSLSessionContext {

    @Override
    public SSLSession getSession(byte[] sessionId) {
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
