package com.tianpengfei.gmkai;

import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SNIMatcher;
import javax.net.ssl.SNIServerName;
import java.security.AlgorithmConstraints;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;

public final class SSLConfiguration {


    // configurations with SSLParameters
    AlgorithmConstraints userSpecifiedAlgorithmConstraints;
    List<ProtocolVersion> enabledProtocols;
    List<CipherSuite> enabledCipherSuites;
    List<CipherSuite> supportedCipherSuites;
    ClientAuthType clientAuthType;
    String identificationProtocol;
    List<SNIServerName> serverNames;
    Collection<SNIMatcher> sniMatchers;
    String[] applicationProtocols;
    boolean preferLocalCipherSuites;
    int maximumPacketSize = 0;


    // Configurations per SSLSocket or SSLEngine instance.
    List<ProtocolVersion> supportedProtocolVersion;
    boolean isClientMode;
    boolean enableSessionCreation;
    List<HandshakeCompletedListener> handshakeCompletedListeners = new LinkedList<>();

    public List<CipherSuite> getSupportedCipherSuites() {

        return supportedCipherSuites;
    }

    public List<CipherSuite> getEnabledCipherSuites() {
        return enabledCipherSuites;
    }

    public void setEnabledCipherSuites(List<CipherSuite> suites) {
        this.enabledCipherSuites = suites;
    }

    public List<ProtocolVersion> getSupportedProtocols() {
        return supportedProtocolVersion;
    }

    public List<ProtocolVersion> getEnabledProtocols() {
        return enabledProtocols;
    }

    public void setEnabledProtocols(List<ProtocolVersion> protocols) {

        this.enabledProtocols = protocols;
    }

    public void addHandshakeCompletedListener(HandshakeCompletedListener listener) {
        handshakeCompletedListeners.add(listener);
    }

    public void removeHandshakeCompletedListener(HandshakeCompletedListener listener) {
        handshakeCompletedListeners.remove(listener);
    }

    public void setUseClientMode(boolean mode) {
        isClientMode = mode;
    }

    public boolean getUseClientMode() {
        return isClientMode;
    }

    public void setNeedClientAuth(boolean need) {
        clientAuthType = need ? ClientAuthType.CLIENT_AUTH_REQUIRED :
                ClientAuthType.CLIENT_AUTH_NONE;
    }

    public boolean getNeedClientAuth() {
        return clientAuthType == ClientAuthType.CLIENT_AUTH_REQUIRED;
    }

    public void setWantClientAuth(boolean want) {

        clientAuthType = want ? ClientAuthType.CLIENT_AUTH_REQUESTED :
                ClientAuthType.CLIENT_AUTH_NONE;
    }

    public boolean getWantClientAuth() {
        return clientAuthType == ClientAuthType.CLIENT_AUTH_REQUESTED;
    }

    public void setEnableSessionCreation(boolean flag) {
        this.enableSessionCreation = flag;
    }

    public boolean getEnableSessionCreation() {
        return enableSessionCreation;
    }

}
