package com.tianpengfei.gmkai;

import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import java.io.IOException;
import java.util.concurrent.locks.ReentrantLock;

public class GMSSLSocket extends SSLSocket {


    private final ReentrantLock socketLock = new ReentrantLock();

    private final GMSSLContextSpi gmsslContextSpi;

    private final TransportContext conContext;

    private final SSLConfiguration sslConfiguration;

    GMSSLSocket(GMSSLContextSpi gmsslContextSpi, SSLConfiguration sslConfiguration) {
        super();
        this.gmsslContextSpi = gmsslContextSpi;
        this.sslConfiguration = sslConfiguration;
        this.conContext = null;
    }

    @Override
    public String[] getSupportedCipherSuites() {

        return new String[0];
    }

    @Override
    public String[] getEnabledCipherSuites() {
        return new String[0];
    }

    @Override
    public void setEnabledCipherSuites(String[] suites) {

    }

    @Override
    public String[] getSupportedProtocols() {
        return new String[0];
    }

    @Override
    public String[] getEnabledProtocols() {
        return new String[0];
    }

    @Override
    public void setEnabledProtocols(String[] protocols) {

    }

    @Override
    public SSLSession getSession() {
        return null;
    }

    @Override
    public void addHandshakeCompletedListener(HandshakeCompletedListener listener) {

    }

    @Override
    public void removeHandshakeCompletedListener(HandshakeCompletedListener listener) {

    }

    @Override
    public void startHandshake() throws IOException {

    }

    @Override
    public void setUseClientMode(boolean mode) {

    }

    @Override
    public boolean getUseClientMode() {
        return false;
    }

    @Override
    public void setNeedClientAuth(boolean need) {

    }

    @Override
    public boolean getNeedClientAuth() {
        return false;
    }

    @Override
    public void setWantClientAuth(boolean want) {

    }

    @Override
    public boolean getWantClientAuth() {
        return false;
    }

    @Override
    public void setEnableSessionCreation(boolean flag) {

    }

    @Override
    public boolean getEnableSessionCreation() {
        return false;
    }
}
