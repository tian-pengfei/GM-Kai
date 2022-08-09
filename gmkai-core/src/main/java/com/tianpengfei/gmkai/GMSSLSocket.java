//package com.tianpengfei.gmkai;
//
//import com.google.common.collect.Lists;
//
//import javax.net.ssl.HandshakeCompletedListener;
//import javax.net.ssl.SSLSession;
//import javax.net.ssl.SSLSocket;
//import java.io.IOException;
//import java.io.InputStream;
//import java.io.OutputStream;
//import java.net.InetAddress;
//import java.net.InetSocketAddress;
//import java.net.Socket;
//import java.net.SocketAddress;
//import java.util.List;
//import java.util.concurrent.locks.ReentrantLock;
//
///**
// * SSL(TSL)+TCP
// * 看做成加强版的Socket比较合适
// */
//public class GMSSLSocket extends SSLSocket implements ConnectSetting {
//
//
//    private final ReentrantLock socketLock = new ReentrantLock();
//
//    private final GMSSLContextData sslContextData;
//
//    private final GMSSLParameters sslParameters;
//
//    private String peerHost;
//
//    protected final Socket tcpSocket;
////
////    protected final boolean autoClose;
//
//    private TransportContext transportContext;
//
//    List<HandshakeCompletedListener> handshakeCompletedListeners = Lists.newArrayList();
//
//
//    public GMSSLSocket(GMSSLContextData sslContextData, GMSSLParameters sslParameters) throws IOException {
//        super();
//        this.sslContextData = sslContextData;
//        this.sslParameters = sslParameters;
//        tcpSocket = new Socket();
//
//        transportContext = new TransportContext(sslParameters, this,
//                tcpSocket.getInputStream(), tcpSocket.getOutputStream());
//    }
//
//    public GMSSLSocket(GMSSLContextData sslContextData, String peerHost, int peerPort) throws IOException {
//
//        super();
//        this.sslContextData = sslContextData;
//        this.peerHost = peerHost;
//        this.sslParameters = sslContextData.getContext().getSupportedSSLParameters();
//        SocketAddress socketAddress =
//                peerHost != null ? new InetSocketAddress(peerHost, peerPort) :
//                        new InetSocketAddress(InetAddress.getByName(null), peerPort);
//        tcpSocket = new Socket();
//
//        tcpSocket.connect(socketAddress, 0);
//
//        transportContext = new TransportContext(sslParameters, this,
//                tcpSocket.getInputStream(), tcpSocket.getOutputStream());
//    }
//
//    public GMSSLSocket(GMSSLContextData sslContextData, InetAddress peerHost, int peerPort) throws IOException {
//        super();
//
//        this.sslContextData = sslContextData;
//        this.sslParameters = sslContextData.getContext().getSupportedSSLParameters();
//        tcpSocket = new Socket();
//        tcpSocket.connect(new InetSocketAddress(peerHost, peerPort), 0);
//        transportContext = new TransportContext(sslParameters, this,
//                tcpSocket.getInputStream(), tcpSocket.getOutputStream());
//    }
//
//    public GMSSLSocket(GMSSLContextData sslContextData, String peerHost, int peerPort, InetAddress localHost, int localPort) throws IOException {
//        super();
//        this.sslContextData = sslContextData;
//        this.peerHost = peerHost;
//        this.sslParameters = sslContextData.getContext().getSupportedSSLParameters();
//        bind(new InetSocketAddress(localHost, localPort));
//        tcpSocket = this;
//        SocketAddress socketAddress =
//                peerHost != null ? new InetSocketAddress(peerHost, peerPort) :
//                        new InetSocketAddress(InetAddress.getByName(null), peerPort);
//        tcpSocket.connect(socketAddress, 0);
//        transportContext = new TransportContext(sslParameters, this,
//                tcpSocket.getInputStream(), tcpSocket.getOutputStream());
//    }
//
//    public GMSSLSocket(GMSSLContextData sslContextData, InetAddress address, int port, InetAddress localAddress, int localPort) throws IOException {
//        super();
//        this.sslContextData = sslContextData;
//        this.sslParameters = sslContextData.getContext().getSupportedSSLParameters();
//        tcpSocket = this;
//        tcpSocket.bind(new InetSocketAddress(localAddress, localPort));
//        tcpSocket.connect(new InetSocketAddress(address, port), 0);
//        transportContext = new TransportContext(sslParameters, this,
//                tcpSocket.getInputStream(), tcpSocket.getOutputStream());
//    }
//
//    public GMSSLSocket(GMSSLContextData sslContextData, Socket s, String peerHost, int peerPort, boolean autoClose) throws IOException {
//
//        super();
//
//        this.sslContextData = sslContextData;
//
//        this.sslParameters = sslContextData.getContext().getSupportedSSLParameters();
//        tcpSocket = s;
//        tcpSocket.connect(new InetSocketAddress(peerHost, peerPort), 0);
//        transportContext = new TransportContext(sslParameters, this,
//                tcpSocket.getInputStream(), tcpSocket.getOutputStream());
//    }
//
//
//    @Override
//    public String[] getSupportedCipherSuites() {
//
//        return CipherSuite.namesOf(sslContextData.getContext().getSupportedCipherSuites());
//    }
//
//    @Override
//    public String[] getEnabledCipherSuites() {
//        return CipherSuite.namesOf(sslParameters.cipherSuites);
//    }
//
//    @Override
//    public void setEnabledCipherSuites(String[] suites) {
//        sslParameters.cipherSuites = CipherSuite.namesOf(suites);
//    }
//
//    // 支持的范围还大一点。根据支持的从中再根据配置筛选出一些当前可用协议。
//    @Override
//    public String[] getSupportedProtocols() {
//        return ProtocolVersion.nameOf(sslContextData.getContext().getSupportedProtocols());
//    }
//
//    /**
//     * 能用的表示当前连接支持那些协议，范围还小一点，从上面中挑选出。当协定好协议时和当前isClient的值或者是添加一些禁用配置
//     * ，对应可用的协议和加密套件也就变得不一样。
//     *
//     * @return
//     */
//    @Override
//    public String[] getEnabledProtocols() {
//        return ProtocolVersion.nameOf(
//                sslParameters.getProtocols());
//    }
//
//    @Override
//    public void setEnabledProtocols(String[] protocols) {
//        sslParameters.setProtocols(ProtocolVersion.nameOf(protocols));
//    }
//
//    @Override
//    public SSLSession getSession() {
//        return transportContext.getSession();
//    }
//
//    @Override
//    public void addHandshakeCompletedListener(HandshakeCompletedListener listener) {
//
//        handshakeCompletedListeners.add(listener);
//    }
//
//    @Override
//    public void removeHandshakeCompletedListener(HandshakeCompletedListener listener) {
//        handshakeCompletedListeners.add(listener);
//    }
//
//    @Override
//    public void startHandshake() throws IOException {
//        transportContext.startHandshake();
//    }
//
//    @Override
//    public void setUseClientMode(boolean mode) {
//        sslParameters.isClientMode = mode;
//    }
//
//    @Override
//    public boolean getUseClientMode() {
//        return sslParameters.isClientMode;
//    }
//
//    @Override
//    public void setNeedClientAuth(boolean need) {
//        sslParameters.clientAuthType = need ?
//                ClientAuthType.CLIENT_AUTH_REQUIRED : ClientAuthType.CLIENT_AUTH_NONE;
//    }
//
//    @Override
//    public boolean getNeedClientAuth() {
//        return sslParameters.clientAuthType == ClientAuthType.CLIENT_AUTH_REQUIRED;
//    }
//
//    @Override
//    public void setWantClientAuth(boolean want) {
//        sslParameters.clientAuthType = want ? ClientAuthType.CLIENT_AUTH_REQUESTED : ClientAuthType.CLIENT_AUTH_NONE;
//    }
//
//    @Override
//    public boolean getWantClientAuth() {
//        return sslParameters.clientAuthType == ClientAuthType.CLIENT_AUTH_REQUESTED;
//
//    }
//
//    @Override
//    public void setEnableSessionCreation(boolean flag) {
//        sslParameters.enableSessionCreation = flag;
//    }
//
//    @Override
//    public boolean getEnableSessionCreation() {
//        return sslParameters.enableSessionCreation;
//    }
//
//    @Override
//    public InputStream getInputStream() throws IOException {
//        return transportContext.getAppInputStream();
//    }
//
//    @Override
//    public SSLSession getHandshakeSession() {
//        return transportContext.getHandshakeSession();
//    }
//
//    @Override
//    public OutputStream getOutputStream() throws IOException {
//        return transportContext.getAppOutPutStream();
//    }
//
//    @Override
//    public void connect(SocketAddress endpoint) throws IOException {
//        tcpSocket.connect(endpoint);
//    }
//
//    @Override
//    public void bind(SocketAddress bindpoint) throws IOException {
//        tcpSocket.bind(bindpoint);
//    }
//
//    @Override
//    public int getPeerPort() {
//        return tcpSocket.getPort();
//    }
//
//
//    @Override
//    public String getPeerHost() {
//        return peerHost;
//    }
//
//    @Override
//    public synchronized void close() throws IOException {
//        tcpSocket.close();
//    }
//}
