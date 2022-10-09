package net.gmkai;


import javax.net.ssl.SSLServerSocket;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;

public class GMKaiServerSocket extends SSLServerSocket {

    private final ContextData contextData;

    private final GMKaiSSLParameters gmKaiSSLParameters;

    protected GMKaiServerSocket(ContextData contextData, GMKaiSSLParameters gmKaiSSLParameters) throws IOException {
        super();
        this.contextData = contextData;
        this.gmKaiSSLParameters = gmKaiSSLParameters.clone();
        this.gmKaiSSLParameters.setUseClientMode(false);
    }

    protected GMKaiServerSocket(int port, int backlog, ContextData contextData, GMKaiSSLParameters gmKaiSSLParameters) throws IOException {
        super(port, backlog);
        this.contextData = contextData;

        this.gmKaiSSLParameters = gmKaiSSLParameters.clone();
        this.gmKaiSSLParameters.setUseClientMode(false);
    }

    protected GMKaiServerSocket(int port, int backlog, InetAddress address, ContextData contextData, GMKaiSSLParameters gmKaiSSLParameters) throws IOException {
        super(port, backlog, address);
        this.contextData = contextData;
        this.gmKaiSSLParameters = gmKaiSSLParameters.clone();
        this.gmKaiSSLParameters.setUseClientMode(false);
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
    public String[] getSupportedCipherSuites() {
        return TLSCipherSuite.namesOf(
                gmKaiSSLParameters.getSupportedCipherSuites());
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
        gmKaiSSLParameters.setEnabledProtocols(ProtocolVersion.namesOf(protocols));
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
    public void setUseClientMode(boolean mode) {
        gmKaiSSLParameters.setUseClientMode(mode);
    }

    @Override
    public boolean getUseClientMode() {
        return gmKaiSSLParameters.getUseClientMode();
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
    public Socket accept() throws IOException {

        GMKaiSocket socket = new GMKaiSocket(contextData, gmKaiSSLParameters);
        implAccept(socket);
        socket.notifyConnected();
        return socket;

    }
}
