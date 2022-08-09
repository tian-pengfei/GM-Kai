package com.tianpengfei.gmkai;

import com.google.common.collect.Lists;

import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLSession;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.util.List;

public class GMKaiSocket extends AbstractGMKaiSocket {

    private final GMSSLContextData sslContextData;

    private final GMSSLParameters sslParameters;

    private TransportContext transportContext;

    List<HandshakeCompletedListener> handshakeCompletedListeners = Lists.newArrayList();

    public GMKaiSocket(GMSSLContextData sslContextData, GMSSLParameters sslParameters) throws IOException {
        super();

        this.sslContextData = sslContextData;

        this.sslParameters = sslParameters;
    }

    GMKaiSocket(String hostname, int port, GMSSLContextData sslContextData, GMSSLParameters sslParameters) throws IOException {
        super(hostname, port);

        this.sslContextData = sslContextData;
        this.sslParameters = sslParameters;

        notifyConnected();

    }

    GMKaiSocket(InetAddress address, int port, GMSSLContextData sslContextData, GMSSLParameters sslParameters) throws IOException {
        super(address, port);

        this.sslContextData = sslContextData;
        this.sslParameters = sslParameters;

        notifyConnected();

    }

    GMKaiSocket(String hostname, int port, InetAddress clientAddress, int clientPort, GMSSLContextData sslContextData, GMSSLParameters sslParameters) throws IOException {
        super(hostname, port, clientAddress, clientPort);

        this.sslContextData = sslContextData;
        this.sslParameters = sslParameters;

        notifyConnected();
    }

    GMKaiSocket(InetAddress address, int port, InetAddress clientAddress, int clientPort, GMSSLContextData sslContextData, GMSSLParameters sslParameters) throws IOException {
        super(address, port, clientAddress, clientPort);
        this.sslContextData = sslContextData;
        this.sslParameters = sslParameters;

        notifyConnected();
    }

    GMKaiSocket(Socket socket, String hostname, int port, boolean autoClose, GMSSLContextData sslContextData, GMSSLParameters sslParameters) throws IOException {
        super(socket, hostname, port, autoClose);

        this.sslContextData = sslContextData;
        this.sslParameters = sslParameters;

        notifyConnected();
    }


    public GMKaiSocket(Socket s, InputStream consumed, boolean autoClose, GMSSLContextData contextData, GMSSLParameters sslParameters) throws IOException {

        super(s, consumed, autoClose);

        this.sslParameters = sslParameters;

        this.sslContextData = contextData;
        notifyConnected();
    }

    protected synchronized void notifyConnected() throws IOException {

        transportContext = new TransportContext(this.sslParameters, sslContextData,getPeerInfoProvider(),
                getUnderlyingInputStream(), getUnderlyingOutputStream());
    }
    @Override
    public String[] getSupportedCipherSuites() {
        return CipherSuite.namesOf(sslContextData.getContext().getSupportedCipherSuites());
    }

    @Override
    public String[] getEnabledCipherSuites() {
        return CipherSuite.namesOf(sslParameters.cipherSuites);
    }

    @Override
    public void setEnabledCipherSuites(String[] suites) {
        sslParameters.cipherSuites = CipherSuite.namesOf(suites);
    }

    @Override
    public String[] getSupportedProtocols() {
        return ProtocolVersion.nameOf(sslContextData.getContext().getSupportedProtocols());
    }

    @Override
    public String[] getEnabledProtocols() {
        return ProtocolVersion.nameOf(
                sslParameters.getProtocols());
    }

    @Override
    public void setEnabledProtocols(String[] protocols) {
        sslParameters.setProtocols(ProtocolVersion.nameOf(protocols));
    }

    @Override
    public SSLSession getSession() {
        return transportContext.getSession();
    }


    @Override
    public void startHandshake() throws IOException {
        transportContext.startHandshake();
    }

    @Override
    public void setUseClientMode(boolean mode) {
        sslParameters.isClientMode = mode;
    }
    @Override
    public boolean getUseClientMode() {
        return sslParameters.isClientMode;
    }

    @Override
    public void setNeedClientAuth(boolean need) {
        sslParameters.clientAuthType = need ?
                ClientAuthType.CLIENT_AUTH_REQUIRED : ClientAuthType.CLIENT_AUTH_NONE;
    }

    @Override
    public boolean getNeedClientAuth() {
        return sslParameters.clientAuthType == ClientAuthType.CLIENT_AUTH_REQUIRED;
    }

    @Override
    public void setWantClientAuth(boolean want) {
        sslParameters.clientAuthType = want ? ClientAuthType.CLIENT_AUTH_REQUESTED : ClientAuthType.CLIENT_AUTH_NONE;
    }

    @Override
    public boolean getWantClientAuth() {
        return sslParameters.clientAuthType == ClientAuthType.CLIENT_AUTH_REQUESTED;

    }

    @Override
    public void setEnableSessionCreation(boolean flag) {
        sslParameters.enableSessionCreation = flag;
    }

    @Override
    public boolean getEnableSessionCreation() {
        return sslParameters.enableSessionCreation;
    }

    @Override
    public InputStream getInputStream() throws IOException {
        return transportContext.getAppInputStream();
    }

    @Override
    public OutputStream getOutputStream() throws IOException {
        return transportContext.getAppOutPutStream();
    }

    @Override
    public SSLSession getHandshakeSession() {
        return transportContext.getHandshakeSession();
    }
}
