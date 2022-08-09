package com.tianpengfei.gmkai;

import javax.net.ssl.SNIMatcher;
import javax.net.ssl.SNIServerName;
import java.security.AlgorithmConstraints;
import java.util.Collection;
import java.util.List;

public class GMSSLParameters {

    AlgorithmConstraints userSpecifiedAlgorithmConstraints;

    List<ProtocolVersion> protocols;

    List<CipherSuite> cipherSuites;

    ClientAuthType clientAuthType;

    String identificationProtocol;

    List<SNIServerName> serverNames;

    Collection<SNIMatcher> sniMatchers;

    String[] applicationProtocols;

    boolean preferLocalCipherSuites;

    int maximumPacketSize = 0;

    boolean isClientMode = true;
    //false的话，就会复用以前的会话，传递消息。
    boolean enableSessionCreation = true;

    GMSSLContextSpi context;

    public GMSSLParameters(GMSSLContextSpi context, List<ProtocolVersion> protocols, List<CipherSuite> cipherSuites) {

        this.context = context;
        this.cipherSuites = cipherSuites;
        this.protocols = protocols;
    }
    public GMSSLParameters(boolean isClientMod,GMSSLContextSpi context, List<ProtocolVersion> protocols, List<CipherSuite> cipherSuites) {

        this(context,protocols,cipherSuites);
        this.isClientMode = isClientMod;
    }

    public AlgorithmConstraints getUserSpecifiedAlgorithmConstraints() {
        return userSpecifiedAlgorithmConstraints;
    }

    public void setUserSpecifiedAlgorithmConstraints(AlgorithmConstraints userSpecifiedAlgorithmConstraints) {
        this.userSpecifiedAlgorithmConstraints = userSpecifiedAlgorithmConstraints;
    }

    public String getIdentificationProtocol() {
        return identificationProtocol;
    }

    public void setIdentificationProtocol(String identificationProtocol) {
        this.identificationProtocol = identificationProtocol;
    }

    public List<SNIServerName> getServerNames() {
        return serverNames;
    }

    public void setServerNames(List<SNIServerName> serverNames) {
        this.serverNames = serverNames;
    }

    public Collection<SNIMatcher> getSniMatchers() {
        return sniMatchers;
    }

    public void setSniMatchers(Collection<SNIMatcher> sniMatchers) {
        this.sniMatchers = sniMatchers;
    }

    public String[] getApplicationProtocols() {
        return applicationProtocols;
    }

    public void setApplicationProtocols(String[] applicationProtocols) {
        this.applicationProtocols = applicationProtocols;
    }

    public boolean isPreferLocalCipherSuites() {
        return preferLocalCipherSuites;
    }

    public void setPreferLocalCipherSuites(boolean preferLocalCipherSuites) {
        this.preferLocalCipherSuites = preferLocalCipherSuites;
    }

    public int getMaximumPacketSize() {
        return maximumPacketSize;
    }

    public void setMaximumPacketSize(int maximumPacketSize) {
        this.maximumPacketSize = maximumPacketSize;
    }

    public ClientAuthType getClientAuthType() {
        return clientAuthType;
    }

    public void setClientAuthType(ClientAuthType clientAuthType) {
        this.clientAuthType = clientAuthType;
    }

    public List<ProtocolVersion> getProtocols() {
        return protocols;
    }

    public void setProtocols(List<ProtocolVersion> protocols) {
        this.protocols = protocols;
    }

    public List<CipherSuite> getCipherSuites() {
        return cipherSuites;
    }

    public void setCipherSuites(List<CipherSuite> cipherSuites) {
        this.cipherSuites = cipherSuites;
    }


    public boolean isClientMode() {
        return isClientMode;
    }

    public void setClientMode(boolean clientMode) {
        isClientMode = clientMode;
    }

    public boolean isEnableSessionCreation() {
        return enableSessionCreation;
    }

    public void setEnableSessionCreation(boolean enableSessionCreation) {
        this.enableSessionCreation = enableSessionCreation;
    }
}
