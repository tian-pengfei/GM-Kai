package net.gmkai;

import javax.net.ssl.SSLServerSocketFactory;
import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;

public class GMKaiServerSocketFactory extends SSLServerSocketFactory {

    protected final ContextData contextData;

    private final GMKaiSSLParameters defaultSSLParameters;

    public GMKaiServerSocketFactory(ContextData contextData) {
        this.contextData = contextData;
        this.defaultSSLParameters = contextData.getDefaultServerSSLParameters();

    }

    @Override
    public ServerSocket createServerSocket(int port) throws IOException {
        return new GMKaiServerSocket(port, 50, contextData, defaultSSLParameters);
    }

    @Override
    public ServerSocket createServerSocket(int port, int backlog) throws IOException {
        return new GMKaiServerSocket(port, backlog, contextData, defaultSSLParameters);
    }

    @Override
    public ServerSocket createServerSocket(int port, int backlog, InetAddress ifAddress) throws IOException {
        return new GMKaiServerSocket(port, backlog, ifAddress, contextData, defaultSSLParameters);
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
}
