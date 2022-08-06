package com.tianpengfei.gmkai;

import javax.crypto.SecretKey;
import javax.net.ssl.ExtendedSSLSession;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSessionContext;
import javax.security.cert.X509Certificate;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.List;

public class GMSSLSession extends ExtendedSSLSession {

    private ProtocolVersion protocolVersion;

    byte[] sessionId;

    private Certificate[] peerCerts;

    private CipherSuite cipherSuite;

//    private SecretKey masterSecret;

    private byte[] masterSecret;

    private long creationTime;

    private long lastUsedTime = 0;

    private String host;

    private int port;

    private Principal peerPrincipal;


    private GMSSLSessionContext sslSessionContext;

    private boolean invalidated = false;

    private Certificate[] localCerts;

    private Principal localPrincipal;


    private PrivateKey[] localPrivateKeys;

    private String[] peerSupportedSignAlgs;      // for certificate

    private boolean useDefaultPeerSignAlgs = false;

    private List<byte[]> statusResponses;

    private SecretKey resumptionMasterSecret;

    private byte[] pskIdentity;

    private final long ticketCreationTime = System.currentTimeMillis();

    private int ticketAgeAdd;

    private int negotiatedMaxFragLen = -1;
    private byte[] preSecret;

    private int maximumPacketSize;

    public GMSSLSession() {

    }

    public GMSSLSession(ProtocolVersion protocolVersion, byte[] sessionId,
                        String host, int port, Certificate[] localCerts, PrivateKey[] localPrivateKeys) {
        this.sessionId = sessionId;
        this.protocolVersion = protocolVersion;
        this.host = host;
        this.port = port;
        this.localCerts = localCerts;
        this.localPrivateKeys = localPrivateKeys;
    }

    public GMSSLSession(ProtocolVersion protocolVersion, byte[] sessionId,
                        String host, int port) {
        this.sessionId = sessionId;
        this.protocolVersion = protocolVersion;
        this.host = host;
        this.port = port;
    }

    @Override
    public byte[] getId() {
        return sessionId;
    }

    @Override
    public SSLSessionContext getSessionContext() {
        return null;
    }

    @Override
    public long getCreationTime() {
        return creationTime;
    }

    @Override
    public long getLastAccessedTime() {
        return lastUsedTime;
    }

    @Override
    public void invalidate() {
        this.invalidated = true;
    }

    @Override
    public boolean isValid() {
        return !invalidated;
    }

    @Override
    public void putValue(String name, Object value) {
        throw new UnsupportedOperationException();
    }

    @Override
    public Object getValue(String name) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void removeValue(String name) {
        throw new UnsupportedOperationException();
    }

    @Override
    public String[] getValueNames() {
        throw new UnsupportedOperationException();
    }

    @Override
    public Certificate[] getPeerCertificates() throws SSLPeerUnverifiedException {

        return peerCerts;
    }

    @Override
    public Certificate[] getLocalCertificates() {
        return localCerts;
    }

    @Override
    public X509Certificate[] getPeerCertificateChain() throws SSLPeerUnverifiedException {
        return null;
    }

    @Override
    public Principal getPeerPrincipal() throws SSLPeerUnverifiedException {
        return peerPrincipal;
    }

    @Override
    public Principal getLocalPrincipal() {
        return localPrincipal;
    }

    @Override
    public String getCipherSuite() {
        return this.cipherSuite.getName();
    }

    public void setCipherSuite(CipherSuite cipherSuite) {
        this.cipherSuite = cipherSuite;
    }

    @Override
    public String getProtocol() {
        return this.protocolVersion.getName();
    }

    @Override
    public String getPeerHost() {
        return this.host;
    }

    @Override
    public int getPeerPort() {
        return this.port;
    }

    @Override
    public int getPacketBufferSize() {
        return maximumPacketSize;
    }

    @Override
    public int getApplicationBufferSize() {
        return 0;
    }

    @Override
    public String[] getLocalSupportedSignatureAlgorithms() {
        return new String[0];
    }

    @Override
    public String[] getPeerSupportedSignatureAlgorithms() {
        return new String[0];
    }

    public void setPeerCerts(Certificate[] peerCerts) {
        this.peerCerts = peerCerts;
    }

    public void setLocalCerts(Certificate[] localCerts) {
        this.localCerts = localCerts;
    }

    public void setPreSecret(byte[] preSecret) {
        this.preSecret = preSecret;
    }

    public byte[] getPreSecret() {
        return preSecret;
    }


    public byte[] getMasterSecret() {
        return masterSecret;
    }

    public void setMasterSecret(byte[] masterSecret) {
        this.masterSecret = masterSecret;
    }
}
