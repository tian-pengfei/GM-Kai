package com.tianpengfei.gmkai;

import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
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

        return CipherSuite.namesOf(sslConfiguration.getSupportedCipherSuites());
    }

    @Override
    public String[] getEnabledCipherSuites() {
        return CipherSuite.namesOf(
                sslConfiguration.getEnabledCipherSuites());
    }

    @Override
    public void setEnabledCipherSuites(String[] suites) {
        sslConfiguration.setEnabledCipherSuites(
                CipherSuite.namesOf(suites));
    }

    @Override
    public String[] getSupportedProtocols() {

        return ProtocolVersion.nameOf(
                sslConfiguration.getSupportedProtocols());
    }

    @Override
    public String[] getEnabledProtocols() {
        return ProtocolVersion.nameOf(
                sslConfiguration.getEnabledProtocols());
    }

    @Override
    public void setEnabledProtocols(String[] protocols) {
        sslConfiguration.setEnabledProtocols(ProtocolVersion.nameOf(protocols));
    }

    @Override
    public SSLSession getSession() {
        return conContext.getSession();
    }

    @Override
    public void addHandshakeCompletedListener(HandshakeCompletedListener listener) {

        sslConfiguration.addHandshakeCompletedListener(listener);
    }

    @Override
    public void removeHandshakeCompletedListener(HandshakeCompletedListener listener) {
        sslConfiguration.removeHandshakeCompletedListener(listener);
    }

    @Override
    public void startHandshake() throws IOException {
        conContext.kickStart();
    }

    @Override
    public void setUseClientMode(boolean mode) {
        sslConfiguration.setUseClientMode(mode);
    }

    @Override
    public boolean getUseClientMode() {
        return sslConfiguration.getUseClientMode();
    }

    @Override
    public void setNeedClientAuth(boolean need) {
        sslConfiguration.setNeedClientAuth(need);
    }

    @Override
    public boolean getNeedClientAuth() {
        return sslConfiguration.getNeedClientAuth();
    }

    @Override
    public void setWantClientAuth(boolean want) {
        sslConfiguration.setWantClientAuth(want);
    }

    @Override
    public boolean getWantClientAuth() {
        return sslConfiguration.getWantClientAuth();
    }

    @Override
    public void setEnableSessionCreation(boolean flag) {
        sslConfiguration.setEnableSessionCreation(flag);
    }

    @Override
    public boolean getEnableSessionCreation() {
        return sslConfiguration.getEnableSessionCreation();
    }

    @Override
    public InputStream getInputStream() throws IOException {
        return conContext.getInputStream();
    }

    @Override
    public SSLSession getHandshakeSession() {
        return conContext.getHandshakeSession();
    }

    @Override
    public OutputStream getOutputStream() throws IOException {
        return conContext.getOutStream();
    }
}
