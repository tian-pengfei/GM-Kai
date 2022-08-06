package com.tianpengfei.gmkai;

import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;

public class GMSSLSocketFactory extends SSLSocketFactory {

    private final GMSSLContextData contextData;

    public GMSSLSocketFactory(GMSSLContextData contextData) {
        this.contextData = contextData;
    }

    @Override
    public String[] getDefaultCipherSuites() {
        return null;
    }

    @Override
    public String[] getSupportedCipherSuites() {

        return CipherSuite.namesOf(
                contextData.getContext().getSupportedCipherSuites());
    }

    @Override
    public Socket createSocket(Socket s, String host, int port, boolean autoClose) throws IOException {

        return new GMSSLSocket(contextData, s, host, port, autoClose);
    }

    @Override
    public Socket createSocket(String host, int port) throws IOException, UnknownHostException {

        return new GMSSLSocket(contextData, host, port);
    }

    @Override
    public Socket createSocket(String host, int port, InetAddress localHost, int localPort) throws IOException, UnknownHostException {
        return new GMSSLSocket(contextData, host, port, localHost, localPort);
    }

    @Override
    public Socket createSocket(InetAddress host, int port) throws IOException {
        return new GMSSLSocket(contextData, host, port);
    }

    @Override
    public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort) throws IOException {
        return new GMSSLSocket(contextData, address, port, localAddress, localPort);
    }
}
