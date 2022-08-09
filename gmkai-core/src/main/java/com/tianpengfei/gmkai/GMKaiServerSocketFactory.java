package com.tianpengfei.gmkai;

import javax.net.ssl.SSLServerSocketFactory;
import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;

public class GMKaiServerSocketFactory extends SSLServerSocketFactory {

    protected final GMSSLContextData contextData;

    public GMKaiServerSocketFactory(GMSSLContextData contextData) {
        this.contextData = contextData;
    }

    @Override
    public ServerSocket createServerSocket(int port) throws IOException {
        return new GMKaiServerSocket(port,contextData);
    }

    @Override
    public ServerSocket createServerSocket(int port, int backlog) throws IOException {
        return new GMKaiServerSocket(port,backlog,contextData);
    }

    @Override
    public ServerSocket createServerSocket(int port, int backlog, InetAddress ifAddress) throws IOException {
        return new GMKaiServerSocket(port,backlog,ifAddress,contextData);
    }


    @Override
    public String[] getDefaultCipherSuites() {
        return CipherSuite.namesOf(
                contextData.getContext().getDefaultCipherSuites(false));
    }

    @Override
    public String[] getSupportedCipherSuites() {
        return CipherSuite.namesOf(
                contextData.getContext().getSupportedCipherSuites());
    }
}
