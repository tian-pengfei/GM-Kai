package net.gmkai;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.Lists;

import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLParameters;
import java.util.List;

public class GMKaiSSLParameters implements Cloneable {

    private final ImmutableList<ProtocolVersion> supportedProtocols;

    private final ImmutableList<TLSCipherSuite> supportedCipherSuites;

    private final ImmutableList<ProtocolVersion> clientDefaultProtocols;

    private final ImmutableList<TLSCipherSuite> clientDefaultCipherSuites;

    private final ImmutableList<ProtocolVersion> serverDefaultProtocols;

    private final ImmutableList<TLSCipherSuite> serverDefaultCipherSuites;

    private List<ProtocolVersion> enabledProtocols;

    private List<TLSCipherSuite> enabledCipherSuites;

    private boolean clientMode;

    private boolean enableSessionCreation = false;

    private final List<HandshakeCompletedListener> handshakeCompletedListeners = Lists.newLinkedList();

    private ClientAuthType clientAuthType = ClientAuthType.CLIENT_AUTH_NONE;

    GMKaiSSLParameters(boolean clientMode, ImmutableList<ProtocolVersion> supportedProtocols,
                       ImmutableList<TLSCipherSuite> supportedCipherSuites,
                       ImmutableList<ProtocolVersion> serverDefaultProtocols,
                       ImmutableList<TLSCipherSuite> serverDefaultCipherSuites,
                       ImmutableList<ProtocolVersion> clientDefaultProtocols,
                       ImmutableList<TLSCipherSuite> clientDefaultCipherSuites) {

        this.clientMode = clientMode;
        this.supportedProtocols = supportedProtocols;
        this.supportedCipherSuites = supportedCipherSuites;
        this.clientDefaultProtocols = clientDefaultProtocols;
        this.clientDefaultCipherSuites = clientDefaultCipherSuites;
        this.serverDefaultProtocols = serverDefaultProtocols;
        this.serverDefaultCipherSuites = serverDefaultCipherSuites;

        enabledProtocols = clientMode ? clientDefaultProtocols : serverDefaultProtocols;
        enabledCipherSuites = clientMode ? clientDefaultCipherSuites : serverDefaultCipherSuites;
    }

    public List<ProtocolVersion> getEnabledProtocols() {
        return enabledProtocols;
    }

    public List<TLSCipherSuite> getEnableCipherSuites() {
        return enabledCipherSuites;
    }

    public void setSSLParameter(SSLParameters sslParameters) {
        String[] s;
        s = sslParameters.getCipherSuites();
        if (s != null) {
            setEnabledCipherSuites(TLSCipherSuite.namesOf(s));
        }
        s = sslParameters.getProtocols();
        if (s != null) {
            setEnabledProtocols(ProtocolVersion.namesOf(s));
        }
        if (sslParameters.getNeedClientAuth()) {
            setNeedClientAuth(true);
        } else {
            setWantClientAuth(sslParameters.getWantClientAuth());
        }
        //todo other property
    }

    public SSLParameters getSSLParameter() {

        SSLParameters sslParameters = new SSLParameters();

        sslParameters.setProtocols(ProtocolVersion.namesOf(enabledProtocols));

        sslParameters.setCipherSuites(TLSCipherSuite.namesOf(enabledCipherSuites));

        if (getNeedClientAuth()) {
            sslParameters.setNeedClientAuth(true);
        } else {
            sslParameters.setWantClientAuth(getWantClientAuth());
        }

        //todo other property

        return sslParameters;

    }

    public List<ProtocolVersion> getSupportedProtocols() {
        return supportedProtocols;
    }


    public List<TLSCipherSuite> getSupportedCipherSuites() {
        return supportedCipherSuites;
    }

    @Override
    protected GMKaiSSLParameters clone() {
        GMKaiSSLParameters gmKaiSSLParameters =
                new GMKaiSSLParameters(
                        clientMode,
                        supportedProtocols,
                        supportedCipherSuites,
                        clientDefaultProtocols,
                        clientDefaultCipherSuites,
                        serverDefaultProtocols,
                        serverDefaultCipherSuites);

        gmKaiSSLParameters.enabledCipherSuites = Lists.newLinkedList(this.enabledCipherSuites);
        gmKaiSSLParameters.enabledProtocols = Lists.newLinkedList(this.enabledProtocols);
        gmKaiSSLParameters.handshakeCompletedListeners.addAll(this.handshakeCompletedListeners);
        return gmKaiSSLParameters;
    }

    public void setEnabledProtocols(List<ProtocolVersion> protocols) {
        verifyProtocolVersion(protocols);
        this.enabledProtocols = protocols;
    }

    public void addHandshakeCompletedListener(HandshakeCompletedListener listener) {
        handshakeCompletedListeners.add(listener);
    }

    public void removeHandshakeCompletedListener(HandshakeCompletedListener listener) {
        handshakeCompletedListeners.remove(listener);
    }

    public void setEnableSessionCreation(boolean flag) {
        enableSessionCreation = flag;
    }

    public boolean getEnableSessionCreation() {
        return enableSessionCreation;
    }

    public void setEnabledCipherSuites(List<TLSCipherSuite> cipherSuites) {
        verifyCipherSuites(cipherSuites);
        enabledCipherSuites = cipherSuites;

    }

    public void setUseClientMode(boolean mode) {
        //have to change enable Protocol and enable CipherSuites,
        // because Client might be different to enable Protocol and CipherSuites from Server

        if (this.clientMode == mode) return;

        //if wasn't modified
        if (enabledProtocols.equals(this.clientMode ? clientDefaultProtocols : serverDefaultProtocols)) {
            enabledProtocols = mode ? clientDefaultProtocols : serverDefaultProtocols;
        }

        //if wasn't modified,
        if (enabledCipherSuites.equals(this.clientMode ? clientDefaultCipherSuites : serverDefaultCipherSuites)) {
            enabledCipherSuites = mode ? clientDefaultCipherSuites : serverDefaultCipherSuites;
        }

        this.clientMode = mode;
    }

    public boolean getUseClientMode() {
        return clientMode;
    }

    private void verifyCipherSuites(List<TLSCipherSuite> suites) {

        for (TLSCipherSuite suite : suites) {
            if (!supportedCipherSuites.contains(suite)) {
                throw new IllegalArgumentException("This cipher suite is not currently supported:" + suite);
            }
        }
    }

    private void verifyProtocolVersion(List<ProtocolVersion> protocolVersions) {

        for (ProtocolVersion pv : protocolVersions) {
            if (!supportedProtocols.contains(pv)) {
                throw new IllegalArgumentException("This protocol is not currently supported:" + pv);
            }
        }
    }

    public void setNeedClientAuth(boolean need) {
        clientAuthType = need ?
                ClientAuthType.CLIENT_AUTH_REQUIRED :
                ClientAuthType.CLIENT_AUTH_NONE;
    }

    public boolean getNeedClientAuth() {

        return clientAuthType ==
                ClientAuthType.CLIENT_AUTH_REQUIRED;
    }

    public void setWantClientAuth(boolean want) {

        clientAuthType = want ?
                ClientAuthType.CLIENT_AUTH_REQUESTED :
                ClientAuthType.CLIENT_AUTH_NONE;
    }

    public boolean getWantClientAuth() {
        return clientAuthType ==
                ClientAuthType.CLIENT_AUTH_REQUESTED;
    }
}
