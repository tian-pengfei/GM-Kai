package net.gmkai;

import com.google.common.collect.Lists;
import net.gmkai.event.GMKaiEventBus;
import net.gmkai.event.HandshakeFinishedEvent;
import net.gmkai.event.HandshakeFinishedListener;
import net.gmkai.event.TLSEventBus;

import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.util.List;

public class GMKaiSocket extends AbstractGMKaiSocket {


    private final GMKaiSSLParameters gmKaiSSLParameters;

    private final InternalContextData internalContextData;

    private SChannel sChannel;

    private final List<HandshakeCompletedListener> handshakeCompletedListeners = Lists.newLinkedList();

    private final TLSEventBus tlsEventBus = new GMKaiEventBus();

    {
        tlsEventBus.register(new GMKaiSocketListener());
    }

    // only be called on server side
    GMKaiSocket(ContextData contextData, GMKaiSSLParameters gmKaiSSLParameters) throws IOException {
        super();
        if (gmKaiSSLParameters.getUseClientMode()) {
            throw new IOException("This instantiation method is only supported for being called on the server side");
        }

        this.gmKaiSSLParameters = gmKaiSSLParameters.clone();

        internalContextData = InternalContextData.getInstance(contextData, this);
    }

    GMKaiSocket(String hostname, int port, ContextData contextData, GMKaiSSLParameters gmKaiSSLParameters) throws IOException {

        super(hostname, port);

        this.gmKaiSSLParameters = gmKaiSSLParameters.clone();
        internalContextData = InternalContextData.getInstance(contextData, this);

        notifyConnected();

    }

    GMKaiSocket(InetAddress address, int port, ContextData contextData, GMKaiSSLParameters gmKaiSSLParameters) throws IOException {
        super(address, port);

        this.gmKaiSSLParameters = gmKaiSSLParameters.clone();
        internalContextData = InternalContextData.getInstance(contextData, this);
        notifyConnected();

    }


    GMKaiSocket(String hostname, int port, InetAddress clientAddress, int clientPort,
                ContextData contextData, GMKaiSSLParameters gmKaiSSLParameters) throws IOException {
        super(hostname, port, clientAddress, clientPort);

        this.gmKaiSSLParameters = gmKaiSSLParameters.clone();
        internalContextData = InternalContextData.getInstance(contextData, this);
        notifyConnected();
    }

    GMKaiSocket(InetAddress address, int port, InetAddress clientAddress, int clientPort,
                ContextData contextData, GMKaiSSLParameters gmKaiSSLParameters) throws IOException {
        super(address, port, clientAddress, clientPort);

        this.gmKaiSSLParameters = gmKaiSSLParameters.clone();
        internalContextData = InternalContextData.getInstance(contextData, this);
        notifyConnected();
    }

    GMKaiSocket(Socket socket, String hostname, int port, boolean autoClose,
                ContextData contextData, GMKaiSSLParameters gmKaiSSLParameters) throws IOException {
        super(socket, hostname, port, autoClose);

        this.gmKaiSSLParameters = gmKaiSSLParameters.clone();
        internalContextData = InternalContextData.getInstance(contextData, this);
        notifyConnected();
    }


    public GMKaiSocket(Socket s, InputStream consumed, boolean autoClose,
                       ContextData contextData, GMKaiSSLParameters gmKaiSSLParameters) throws IOException {

        super(s, consumed, autoClose);

        this.gmKaiSSLParameters = gmKaiSSLParameters.clone();
        internalContextData = InternalContextData.getInstance(contextData, this);
        notifyConnected();
    }

    protected synchronized void notifyConnected() throws IOException {
        sChannel = new SChannel(
                tlsEventBus,
                internalContextData,
                gmKaiSSLParameters,
                getPeerInfoProvider(),
                getUnderlyingInputStream(),
                getUnderlyingOutputStream());
    }

    @Override
    public String[] getSupportedCipherSuites() {
        return TLSCipherSuite.namesOf(
                gmKaiSSLParameters.getSupportedCipherSuites());
    }

    @Override
    public String[] getEnabledCipherSuites() {
        return TLSCipherSuite.namesOf(
                gmKaiSSLParameters.getEnableCipherSuites());
    }

    @Override
    public void setEnabledCipherSuites(String[] suites) {
        gmKaiSSLParameters.setEnabledCipherSuites(TLSCipherSuite.namesOf(suites));
    }

    @Override
    public String[] getSupportedProtocols() {
        return ProtocolVersion.namesOf(
                gmKaiSSLParameters.getSupportedProtocols());
    }

    @Override
    public String[] getEnabledProtocols() {
        return ProtocolVersion.namesOf(
                gmKaiSSLParameters.getEnabledProtocols());
    }

    @Override
    public void setEnabledProtocols(String[] protocols) {
        gmKaiSSLParameters.setEnabledProtocols(ProtocolVersion.namesOf(
                protocols));
    }

    @Override
    public SSLSession getHandshakeSession() {
        return sChannel.getHandshakeSession();
    }

    @Override
    public SSLSession getSession() {
        try {
            return sChannel.getSession();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    @Override
    public void addHandshakeCompletedListener(HandshakeCompletedListener listener) {
        handshakeCompletedListeners.add(listener);
    }

    @Override
    public void removeHandshakeCompletedListener(HandshakeCompletedListener listener) {
        handshakeCompletedListeners.remove(listener);
    }

    @Override
    public void startHandshake() throws IOException {
        sChannel.startHandshake();
    }

    @Override
    public void setUseClientMode(boolean mode) {

        gmKaiSSLParameters.setUseClientMode(mode);
    }

    @Override
    public boolean getUseClientMode() {
        return gmKaiSSLParameters.getUseClientMode();
    }

    @Override
    public void setNeedClientAuth(boolean need) {
        gmKaiSSLParameters.setNeedClientAuth(need);
    }

    @Override
    public boolean getNeedClientAuth() {
        return gmKaiSSLParameters.getNeedClientAuth();
    }

    @Override
    public void setWantClientAuth(boolean want) {

        gmKaiSSLParameters.setWantClientAuth(want);
    }

    @Override
    public boolean getWantClientAuth() {
        return gmKaiSSLParameters.getWantClientAuth();

    }

    @Override
    public void setEnableSessionCreation(boolean flag) {
        gmKaiSSLParameters.setEnableSessionCreation(flag);
    }

    @Override
    public boolean getEnableSessionCreation() {
        return gmKaiSSLParameters.getEnableSessionCreation();
    }

    @Override
    public OutputStream getOutputStream() throws IOException {
        return sChannel.getSOutStream();
    }

    @Override
    public InputStream getInputStream() throws IOException {
        return sChannel.getSInputStream();
    }

    @Override
    public void setSSLParameters(SSLParameters params) {
        gmKaiSSLParameters.setSSLParameter(params);
    }

    private class GMKaiSocketListener implements HandshakeFinishedListener {

        @Override
        public void handshakeFinished(HandshakeFinishedEvent event) {
            handshakeCompletedListeners.forEach(listener -> listener.handshakeCompleted(
                    new HandshakeCompletedEvent(GMKaiSocket.this, getSession())));
        }
    }
}
