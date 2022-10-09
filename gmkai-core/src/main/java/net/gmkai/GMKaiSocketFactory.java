package net.gmkai;

import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;

public class GMKaiSocketFactory extends SSLSocketFactory {

    private final ContextData contextData;

    private final GMKaiSSLParameters defaultSSLParameters;


    public GMKaiSocketFactory(ContextData contextData) {
        this.contextData = contextData;
        this.defaultSSLParameters = contextData.getDefaultClientSSLParameters();
    }

    @Override
    public String[] getDefaultCipherSuites() {
        return TLSCipherSuite.namesOf(
                defaultSSLParameters.getEnableCipherSuites());
    }

    @Override
    public String[] getSupportedCipherSuites() {
        return TLSCipherSuite.namesOf(
                defaultSSLParameters.getSupportedCipherSuites());
    }

    @Override
    public Socket createSocket(Socket s, String host, int port, boolean autoClose) throws IOException {

        return new GMKaiSocket(s, host, port, autoClose, contextData, defaultSSLParameters);
    }

    @Override
    public Socket createSocket(String host, int port) throws IOException, UnknownHostException {
        return new GMKaiSocket(host, port, contextData, defaultSSLParameters);
    }

    @Override
    public Socket createSocket(String host, int port, InetAddress localHost, int localPort) throws IOException, UnknownHostException {
        return new GMKaiSocket(host, port, localHost, localPort, contextData, defaultSSLParameters);
    }

    @Override
    public Socket createSocket(InetAddress host, int port) throws IOException {
        return new GMKaiSocket(host, port, contextData, defaultSSLParameters);
    }

    @Override
    public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort) throws IOException {
        return new GMKaiSocket(address, port, localAddress, localPort, contextData, defaultSSLParameters);
    }
}
