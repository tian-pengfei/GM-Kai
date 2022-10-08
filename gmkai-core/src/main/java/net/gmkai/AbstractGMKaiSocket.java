package net.gmkai;

import javax.net.ssl.SSLSocket;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.SequenceInputStream;
import java.net.*;
import java.nio.channels.SocketChannel;

import static com.google.common.base.Preconditions.checkNotNull;

public abstract class AbstractGMKaiSocket extends SSLSocket {

    final Socket socket;

    //Use only in delegate cases
    private final boolean autoClose;

    private String peerHostname;

    private final int peerPort;

    private int readTimeoutMilliseconds;

    private final InputStream consumedInput;

    private final PeerInfoProvider peerInfoProvider = new PeerInfoProvider() {
        @Override
        public String getHostname() {
            return AbstractGMKaiSocket.this.getHostname();
        }

        @Override
        public int getPort() {
            return AbstractGMKaiSocket.this.getPort();
        }
    };


    AbstractGMKaiSocket() throws IOException {
        this.socket = this;
        this.peerHostname = null;
        this.peerPort = -1;
        this.autoClose = false;
        this.consumedInput = null;
    }

    AbstractGMKaiSocket(String hostname, int port) throws IOException {
        super(hostname, port);
        this.socket = this;
        this.peerHostname = hostname;
        this.peerPort = port;
        this.autoClose = false;
        this.consumedInput = null;

    }

    AbstractGMKaiSocket(InetAddress address, int port) throws IOException {
        super(address, port);
        this.socket = this;
        this.peerHostname = null;
        this.peerPort = -1;
        this.autoClose = false;
        this.consumedInput = null;

    }

    AbstractGMKaiSocket(String hostname, int port, InetAddress clientAddress, int clientPort)
            throws IOException {
        super(hostname, port, clientAddress, clientPort);
        this.socket = this;
        this.peerHostname = hostname;
        this.peerPort = port;
        this.autoClose = false;
        this.consumedInput = null;

    }

    AbstractGMKaiSocket(InetAddress address, int port, InetAddress clientAddress,
                        int clientPort) throws IOException {
        super(address, port, clientAddress, clientPort);
        this.socket = this;
        this.peerHostname = null;
        this.peerPort = -1;
        this.autoClose = false;
        this.consumedInput = null;

    }

    AbstractGMKaiSocket(Socket socket, String hostname, int port, boolean autoClose)
            throws IOException {
        this.socket = checkNotNull(socket, "socket");
        this.peerHostname = hostname;
        this.peerPort = port;
        this.autoClose = autoClose;
        this.consumedInput = null;

    }

    public AbstractGMKaiSocket(Socket socket, InputStream consumed, boolean autoClose) {

        this.socket = checkNotNull(socket, "socket");
        this.peerHostname = null;
        this.peerPort = -1;
        this.autoClose = autoClose;
        this.consumedInput = consumed;

    }


    @Override
    public final void connect(SocketAddress endpoint) throws IOException {
        connect(endpoint, 0);
    }


    @Override
    public final void connect(SocketAddress endpoint, int timeout) throws IOException {
        if (peerHostname == null && endpoint instanceof InetSocketAddress) {
            peerHostname = ((InetSocketAddress) endpoint).getHostString();
        }

        if (isDelegating()) {
            socket.connect(endpoint, timeout);
        } else {
            super.connect(endpoint, timeout);
        }
    }

    @Override
    public void bind(SocketAddress bindpoint) throws IOException {
        if (isDelegating()) {
            socket.bind(bindpoint);
        } else {
            super.bind(bindpoint);
        }
    }

    @Override
    public void close() throws IOException {
        if (isDelegating()) {
            if (autoClose && !socket.isClosed()) {
                socket.close();
            }
        } else {
            if (!super.isClosed()) {
                super.close();
            }
        }
    }

    @Override
    public InetAddress getInetAddress() {
        if (isDelegating()) {
            return socket.getInetAddress();
        }
        return super.getInetAddress();
    }

    @Override
    public InetAddress getLocalAddress() {
        if (isDelegating()) {
            return socket.getLocalAddress();
        }
        return super.getLocalAddress();
    }

    @Override
    public int getLocalPort() {
        if (isDelegating()) {
            return socket.getLocalPort();
        }
        return super.getLocalPort();
    }

    @Override
    public SocketAddress getRemoteSocketAddress() {
        if (isDelegating()) {
            return socket.getRemoteSocketAddress();
        }
        return super.getRemoteSocketAddress();
    }

    @Override
    public SocketAddress getLocalSocketAddress() {
        if (isDelegating()) {
            return socket.getLocalSocketAddress();
        }
        return super.getLocalSocketAddress();
    }

    @Override
    public final int getPort() {
        if (isDelegating()) {
            return socket.getPort();
        }

        if (peerPort != -1) {

            return peerPort;
        }
        return super.getPort();
    }

    @Override
    public final void setSoTimeout(int readTimeoutMilliseconds) throws SocketException {
        if (isDelegating()) {
            socket.setSoTimeout(readTimeoutMilliseconds);
        } else {
            super.setSoTimeout(readTimeoutMilliseconds);
            this.readTimeoutMilliseconds = readTimeoutMilliseconds;
        }
    }

    @Override
    @SuppressWarnings("UnsynchronizedOverridesSynchronized")
    public final int getSoTimeout() throws SocketException {
        if (isDelegating()) {
            return socket.getSoTimeout();
        }
        return readTimeoutMilliseconds;
    }

    @Override
    public final void sendUrgentData(int data) throws IOException {
        throw new SocketException("Method sendUrgentData() is not supported.");
    }

    @Override
    public final void setOOBInline(boolean on) throws SocketException {
        throw new SocketException("Method setOOBInline() is not supported.");
    }

    @Override
    public boolean getOOBInline() throws SocketException {
        return false;
    }

    @Override
    public SocketChannel getChannel() {
        if (isDelegating()) {
            return socket.getChannel();
        } else {
            return super.getChannel();
        }
    }

    public abstract InputStream getInputStream() throws IOException;

    public abstract OutputStream getOutputStream() throws IOException;

    @Override
    public void setTcpNoDelay(boolean on) throws SocketException {
        if (isDelegating()) {
            socket.setTcpNoDelay(on);
        } else {
            super.setTcpNoDelay(on);
        }
    }

    @Override
    public boolean getTcpNoDelay() throws SocketException {
        if (isDelegating()) {
            return socket.getTcpNoDelay();
        }
        return super.getTcpNoDelay();
    }

    @Override
    public void setSoLinger(boolean on, int linger) throws SocketException {
        if (isDelegating()) {
            socket.setSoLinger(on, linger);
        } else {
            super.setSoLinger(on, linger);
        }
    }

    @Override
    public int getSoLinger() throws SocketException {
        if (isDelegating()) {
            return socket.getSoLinger();
        }
        return super.getSoLinger();
    }

    @Override
    @SuppressWarnings("UnsynchronizedOverridesSynchronized")
    public void setSendBufferSize(int size) throws SocketException {
        if (isDelegating()) {
            socket.setSendBufferSize(size);
        } else {
            super.setSendBufferSize(size);
        }
    }

    @Override
    public int getSendBufferSize() throws SocketException {
        if (isDelegating()) {
            return socket.getSendBufferSize();
        }
        return super.getSendBufferSize();
    }

    @Override
    public void setReceiveBufferSize(int size) throws SocketException {
        if (isDelegating()) {
            socket.setReceiveBufferSize(size);
        } else {
            super.setReceiveBufferSize(size);
        }
    }

    @Override
    public int getReceiveBufferSize() throws SocketException {
        if (isDelegating()) {
            return socket.getReceiveBufferSize();
        }
        return super.getReceiveBufferSize();
    }

    @Override
    public void setKeepAlive(boolean on) throws SocketException {
        if (isDelegating()) {
            socket.setKeepAlive(on);
        } else {
            super.setKeepAlive(on);
        }
    }

    @Override
    public boolean getKeepAlive() throws SocketException {
        if (isDelegating()) {
            return socket.getKeepAlive();
        }
        return super.getKeepAlive();
    }

    @Override
    public void setTrafficClass(int tc) throws SocketException {
        if (isDelegating()) {
            socket.setTrafficClass(tc);
        } else {
            super.setTrafficClass(tc);
        }
    }

    @Override
    public int getTrafficClass() throws SocketException {
        if (isDelegating()) {
            return socket.getTrafficClass();
        }
        return super.getTrafficClass();
    }

    @Override
    public void setReuseAddress(boolean on) throws SocketException {
        if (isDelegating()) {
            socket.setReuseAddress(on);
        } else {
            super.setReuseAddress(on);
        }
    }

    @Override
    public boolean getReuseAddress() throws SocketException {
        if (isDelegating()) {
            return socket.getReuseAddress();
        }
        return super.getReuseAddress();
    }

    @Override
    public void shutdownInput() throws IOException {
        if (isDelegating()) {
            socket.shutdownInput();
        } else {
            super.shutdownInput();
        }
    }

    @Override
    public void shutdownOutput() throws IOException {
        if (isDelegating()) {
            socket.shutdownOutput();
        } else {
            super.shutdownOutput();
        }
    }

    @Override
    public boolean isConnected() {
        if (isDelegating()) {
            return socket.isConnected();
        }
        return super.isConnected();
    }

    @Override
    public boolean isBound() {
        if (isDelegating()) {
            return socket.isBound();
        }
        return super.isBound();
    }

    @Override
    public boolean isClosed() {
        if (isDelegating()) {
            return socket.isClosed();
        }
        return super.isClosed();
    }

    @Override
    public boolean isInputShutdown() {
        if (isDelegating()) {
            return socket.isInputShutdown();
        }
        return super.isInputShutdown();
    }

    @Override
    public boolean isOutputShutdown() {
        if (isDelegating()) {
            return socket.isOutputShutdown();
        }
        return super.isOutputShutdown();
    }

    @Override
    public void setPerformancePreferences(int connectionTime, int latency, int bandwidth) {
        if (isDelegating()) {
            socket.setPerformancePreferences(connectionTime, latency, bandwidth);
        } else {
            super.setPerformancePreferences(connectionTime, latency, bandwidth);
        }
    }

    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder("SSL socket over ");
        if (isDelegating()) {
            builder.append(socket.toString());
        } else {
            builder.append(super.toString());
        }
        return builder.toString();
    }

    String getHostname() {
        return peerHostname;
    }

    void setHostname(String hostname) {
        peerHostname = hostname;
    }

    final void checkOpen() throws SocketException {
        if (isClosed()) {
            throw new SocketException("Socket is closed");
        }
    }

    private boolean isDelegating() {
        return socket != null && socket != this;
    }


    protected InputStream getUnderlyingInputStream() throws IOException {
        if (isDelegating()) {

            if (consumedInput != null) {
                return new SequenceInputStream(consumedInput,
                        socket.getInputStream());
            }

            return socket.getInputStream();
        } else {
            return super.getInputStream();
        }
    }


    protected OutputStream getUnderlyingOutputStream() throws IOException {
        if (isDelegating()) {
            return socket.getOutputStream();
        } else {
            return super.getOutputStream();
        }
    }

    public PeerInfoProvider getPeerInfoProvider() {

        return peerInfoProvider;
    }
}
