package com.tianpengfei.gmkai;

import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;
import java.io.InputStream;
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
        GMSSLParameters sslParameters = contextData.getContext().getDefaultSSLParameters(true);

        return new GMKaiSocket( s, host, port, autoClose,contextData, sslParameters);
    }

    @Override
    public Socket createSocket(String host, int port) throws IOException, UnknownHostException {
        GMSSLParameters sslParameters = contextData.getContext().getDefaultSSLParameters(true);

        return new GMKaiSocket(host, port,contextData, sslParameters);
    }

    @Override
    public Socket createSocket(String host, int port, InetAddress localHost, int localPort) throws IOException, UnknownHostException {
        GMSSLParameters sslParameters = contextData.getContext().getDefaultSSLParameters(true);

        return new GMKaiSocket( host, port, localHost, localPort,contextData, sslParameters);
    }

    @Override
    public Socket createSocket(InetAddress host, int port) throws IOException {
        GMSSLParameters sslParameters = contextData.getContext().getDefaultSSLParameters(true);

        return new GMKaiSocket( host, port,contextData, sslParameters);
    }

    @Override
    public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort) throws IOException {
        GMSSLParameters sslParameters = contextData.getContext().getDefaultSSLParameters(true);

        return new GMKaiSocket(address, port, localAddress, localPort,contextData, sslParameters);
    }

    @Override
    public Socket createSocket(Socket s, InputStream consumed,
                               boolean autoClose) throws IOException {

        GMSSLParameters sslParameters = contextData.getContext().getDefaultSSLParameters(false);

        return new GMKaiSocket(s, consumed, autoClose, contextData,sslParameters);
    }
}
