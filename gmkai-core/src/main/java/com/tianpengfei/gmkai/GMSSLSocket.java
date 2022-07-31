package com.tianpengfei.gmkai;

import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.util.List;
import java.util.concurrent.locks.ReentrantLock;

public class GMSSLSocket extends SSLSocket {


    private final ReentrantLock socketLock = new ReentrantLock();

    private final GMContextData contextData;

    private final GMSSLParameters sslParameters;

    private boolean isClientMode = true;

    private String peerHost;

    //false的话，就会复用以前的会话，传递消息。
    protected boolean enableSessionCreation = true;

//    protected final Socket wrapSocket;
//
//    protected final boolean autoClose;

    private final TransportContext conContext = new TransportContext();


    List<HandshakeCompletedListener> handshakeCompletedListeners;

    GMSSLSocket(GMContextData contextData, GMSSLParameters sslParameters) {
        super();
        this.contextData = contextData;
        this.sslParameters = sslParameters;
//        this.conContext = null;
    }

    GMSSLSocket(GMContextData contextData, String peerHost, int peerPort) throws IOException {

        super();
        this.contextData = contextData;
        this.peerHost = peerHost;
        this.sslParameters = contextData.getContext().getSupportedSSLParameters(isClientMode);
        SocketAddress socketAddress =
                peerHost != null ? new InetSocketAddress(peerHost, peerPort) :
                        new InetSocketAddress(InetAddress.getByName(null), peerPort);
        connect(socketAddress, 0);

    }

    GMSSLSocket(GMContextData contextData, InetAddress peerHost, int peerPort) throws IOException {
        super();

        this.contextData = contextData;
        this.sslParameters = contextData.getContext().getSupportedSSLParameters(isClientMode);
        connect(new InetSocketAddress(peerHost, peerPort), 0);

    }

    GMSSLSocket(GMContextData contextData, String peerHost, int peerPort, InetAddress localHost, int localPort) throws IOException {
        super();
        this.contextData = contextData;
        this.peerHost = peerHost;
        this.sslParameters = contextData.getContext().getSupportedSSLParameters(isClientMode);
        bind(new InetSocketAddress(localHost, localPort));

        SocketAddress socketAddress =
                peerHost != null ? new InetSocketAddress(peerHost, peerPort) :
                        new InetSocketAddress(InetAddress.getByName(null), peerPort);
        connect(socketAddress, 0);

    }

    GMSSLSocket(GMContextData contextData, InetAddress address, int port, InetAddress localAddress, int localPort) throws IOException {
        super();
        this.contextData = contextData;
        this.sslParameters = contextData.getContext().getSupportedSSLParameters(isClientMode);
        bind(new InetSocketAddress(localAddress, localPort));

        connect(new InetSocketAddress(address, port), 0);

    }


    @Override
    public String[] getSupportedCipherSuites() {

        return CipherSuite.namesOf(contextData.getContext().getSupportedCipherSuites());
    }

    @Override
    public String[] getEnabledCipherSuites() {
        return CipherSuite.namesOf(sslParameters.cipherSuites);
    }

    @Override
    public void setEnabledCipherSuites(String[] suites) {
        sslParameters.cipherSuites = CipherSuite.namesOf(suites);
    }

    // 支持的范围还大一点。根据支持的从中再根据配置筛选出一些当前可用协议。
    @Override
    public String[] getSupportedProtocols() {
        return ProtocolVersion.nameOf(contextData.getContext().getSupportedProtocols(isClientMode));
    }

    /**
     * 能用的表示当前连接支持那些协议，范围还小一点，从上面中挑选出。当协定好协议时和当前isClient的值或者是添加一些禁用配置
     * ，对应可用的协议和加密套件也就变得不一样。
     *
     * @return
     */
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
        return conContext.getSession();
    }

    @Override
    public void addHandshakeCompletedListener(HandshakeCompletedListener listener) {

        handshakeCompletedListeners.add(listener);
    }

    @Override
    public void removeHandshakeCompletedListener(HandshakeCompletedListener listener) {
        handshakeCompletedListeners.add(listener);
    }

    @Override
    public void startHandshake() throws IOException {
        conContext.kickStart();
    }

    @Override
    public void setUseClientMode(boolean mode) {
        isClientMode = mode;
    }

    @Override
    public boolean getUseClientMode() {
        return isClientMode;
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
        enableSessionCreation = flag;
    }

    @Override
    public boolean getEnableSessionCreation() {
        return enableSessionCreation;
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

    @Override
    public void connect(SocketAddress endpoint) throws IOException {

        super.connect(endpoint);
    }
}
