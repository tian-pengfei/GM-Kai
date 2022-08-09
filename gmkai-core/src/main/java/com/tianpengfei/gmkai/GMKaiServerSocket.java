package com.tianpengfei.gmkai;


import javax.net.ssl.SSLServerSocket;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;

public class GMKaiServerSocket extends SSLServerSocket {

    protected final GMSSLContextData contextData;

    protected final GMSSLParameters sslParameters;

    protected final boolean isClientMode = false;

    protected GMKaiServerSocket(GMSSLContextData contextData) throws IOException {
        super();
        this.contextData = contextData;

        this.sslParameters = contextData.getContext().getDefaultSSLParameters(isClientMode);
    }

    protected GMKaiServerSocket(int port, GMSSLContextData contextData) throws IOException {
        super(port);
        this.contextData = contextData;
        this.sslParameters = contextData.getContext().getDefaultSSLParameters(isClientMode);

    }

    protected GMKaiServerSocket(int port, int backlog, GMSSLContextData contextData) throws IOException {
        super(port, backlog);
        this.contextData = contextData;
        this.sslParameters = contextData.getContext().getDefaultSSLParameters(isClientMode);

    }

    protected GMKaiServerSocket(int port, int backlog, InetAddress address, GMSSLContextData contextData) throws IOException {
        super(port, backlog, address);
        this.contextData = contextData;
        this.sslParameters = contextData.getContext().getDefaultSSLParameters(isClientMode);

    }

    @Override
    public String[] getEnabledCipherSuites() {
        return CipherSuite.namesOf(
                sslParameters.getCipherSuites());
    }

    @Override
    public void setEnabledCipherSuites(String[] suites) {
        sslParameters.setCipherSuites(CipherSuite.namesOf(suites));
    }

    @Override
    public String[] getSupportedCipherSuites() {
        return CipherSuite.namesOf(
                contextData.getContext().getSupportedCipherSuites());
    }

    @Override
    public String[] getSupportedProtocols() {

        return ProtocolVersion.nameOf(
                contextData.getContext().getSupportedProtocols());
    }

    @Override
    public String[] getEnabledProtocols() {
        return sslParameters.applicationProtocols;
    }

    @Override
    public void setEnabledProtocols(String[] protocols) {
        sslParameters.setProtocols(ProtocolVersion.nameOf(protocols));
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
    public void setUseClientMode(boolean mode) {
        if(sslParameters.isClientMode!=mode){

            sslParameters.setProtocols(contextData.getContext().getDefaultProtocols(mode));
            sslParameters.setCipherSuites(contextData.getContext().getDefaultCipherSuites(mode));
        }

        sslParameters.setClientMode(mode);
    }

    @Override
    public boolean getUseClientMode() {
        return sslParameters.isClientMode;
    }

    @Override
    public void setEnableSessionCreation(boolean flag) {
        sslParameters.setEnableSessionCreation(flag);
    }

    @Override
    public boolean getEnableSessionCreation() {
        return sslParameters.enableSessionCreation;
    }

    @Override
    public Socket accept() throws IOException {

        GMKaiSocket socket = new GMKaiSocket(contextData,sslParameters);
        implAccept(socket);
        socket.notifyConnected();
        return socket;

    }
}
