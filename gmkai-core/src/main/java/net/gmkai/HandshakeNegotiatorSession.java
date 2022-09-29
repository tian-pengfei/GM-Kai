package net.gmkai;

public class HandshakeNegotiatorSession {

    private byte[] clientRandom;

    private byte[] serverRandom;

    private byte[] sessionId;

    private GMKaiExtendedSSLSession sslSession;

    private boolean reusable = false;

    private ProtocolVersion protocolVersion;

    private TLSCipherSuite tlsCipherSuite;

    private CompressionMethod compressionMethod;

    public HandshakeNegotiatorSession() {

    }

    private HandshakeNegotiatorSession(byte[] clientRandom,
                                       byte[] serverRandom,
                                       byte[] sessionId,
                                       GMKaiExtendedSSLSession sslSession,
                                       boolean reusable,
                                       ProtocolVersion protocolVersion,
                                       CompressionMethod compressionMethod) {
        this.clientRandom = clientRandom;
        this.serverRandom = serverRandom;
        this.sessionId = sessionId;
        this.sslSession = sslSession;
        this.reusable = reusable;
        this.protocolVersion = protocolVersion;
        this.compressionMethod = compressionMethod;
    }

    void setClientRandom(byte[] clientRandom) {
        this.clientRandom = clientRandom;
    }

    void setServerRandom(byte[] serverRandom) {
        this.serverRandom = serverRandom;
    }

    /**
     * default false
     *
     * @return reusable
     */
    boolean reusable() {
        return reusable;
    }

    /**
     * reusable-->true
     */
    void makeReusable() {
        reusable = false;
    }


    byte[] getClientRandom() {
        return clientRandom;
    }

    byte[] getServerRandom() {
        return serverRandom;
    }

    ProtocolVersion getVersion() {
        return protocolVersion;
    }


    public HandshakeNegotiatorSession clone() {

        return new HandshakeNegotiatorSession(
                clientRandom,
                serverRandom,
                sessionId,
                sslSession,
                reusable,
                protocolVersion,
                compressionMethod);
    }

    public ProtocolVersion getProtocolVersion() {
        return protocolVersion;
    }

    public void setProtocolVersion(ProtocolVersion protocolVersion) {
        this.protocolVersion = protocolVersion;
    }

    public byte[] getSessionId() {
        return sessionId;
    }

    public void setSessionId(byte[] sessionId) {
        this.sessionId = sessionId;
    }

    public TLSCipherSuite getTlsCipherSuite() {
        return tlsCipherSuite;
    }

    public void setTlsCipherSuite(TLSCipherSuite tlsCipherSuite) {
        this.tlsCipherSuite = tlsCipherSuite;
    }

    public CompressionMethod getCompressionMethod() {
        return compressionMethod;
    }

    public void setCompressionMethod(CompressionMethod compressionMethod) {
        this.compressionMethod = compressionMethod;
    }

    NegotiationResult getNegotiationResult() {

        return new NegotiationResult(protocolVersion, clientRandom, serverRandom, sessionId, tlsCipherSuite, reusable);
    }

    public GMKaiExtendedSSLSession getSslSession() {
        return sslSession;
    }

    public void setSslSession(GMKaiExtendedSSLSession sslSession) {
        this.sslSession = sslSession;
    }

}
