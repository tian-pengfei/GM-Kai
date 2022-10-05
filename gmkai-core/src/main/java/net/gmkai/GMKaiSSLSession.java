package net.gmkai;

import javax.net.ssl.ExtendedSSLSession;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSessionContext;
import javax.security.cert.X509Certificate;
import java.security.Principal;
import java.security.cert.Certificate;
import java.util.concurrent.atomic.AtomicLong;

//todo
public class GMKaiSSLSession implements GMKaiExtendedSSLSession {

    private ProtocolVersion protocolVersion;

    private byte[] sessionId;

    private Certificate[] peerCerts;

    private Certificate[] localCerts;

    private TLSCipherSuite tlsCipherSuite;

    private CompressionMethod compressionMethod;

    protected final String peerHost;

    protected final int peerPort;

    protected final long creationTime;

    protected final AtomicLong lastAccessedTime;


    private byte[] masterSecrete;

    public GMKaiSSLSession(byte[] sessionId,
                           String peerHost,
                           int peerPort,
                           TLSCipherSuite tlsCipherSuite,
                           CompressionMethod compressionMethod) {
        this.sessionId = sessionId;
        this.peerHost = peerHost;
        this.peerPort = peerPort;

        this.creationTime = System.currentTimeMillis();
        this.lastAccessedTime = new AtomicLong(creationTime);

        this.tlsCipherSuite = tlsCipherSuite;
        this.compressionMethod = compressionMethod;
    }

    public void putTLSCipherSuite(TLSCipherSuite tlsCipherSuite) {
        this.tlsCipherSuite = tlsCipherSuite;
    }

    @Override
    public void putMasterSecret(byte[] masterSecret) {
        this.masterSecrete = masterSecret;
    }

    @Override
    public byte[] getMasterSecret() {
        return this.masterSecrete;
    }


    @Override
    public void putPeerCertificate(Certificate[] peerCerts) {
        this.peerCerts = peerCerts;
    }

    @Override
    public void putLocalCertificate(Certificate[] localCerts) {
        this.localCerts = localCerts;
    }

    @Override
    public String[] getLocalSupportedSignatureAlgorithms() {
        //todo
        throw new UnsupportedOperationException();
    }

    @Override
    public String[] getPeerSupportedSignatureAlgorithms() {
        //todo
        throw new UnsupportedOperationException();
    }

    @Override
    public boolean isFipsMode() {
        //todo
        throw new UnsupportedOperationException();
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
        return lastAccessedTime.get();
    }

    @Override
    public void invalidate() {

    }

    @Override
    public boolean isValid() {
        return false;
    }

    @Override
    public void putValue(String s, Object o) {

    }

    @Override
    public Object getValue(String s) {
        return null;
    }

    @Override
    public void removeValue(String s) {

    }

    @Override
    public String[] getValueNames() {
        return new String[0];
    }

    @Override
    public Certificate[] getPeerCertificates() throws SSLPeerUnverifiedException {
        if (peerCerts == null) throw new SSLPeerUnverifiedException("Certificates have not been verified");
        return peerCerts;
    }

    @Override
    public Certificate[] getLocalCertificates() {
        return localCerts;
    }

    @Override
    public X509Certificate[] getPeerCertificateChain() throws SSLPeerUnverifiedException {
        throw new UnsupportedOperationException();
    }

    @Override
    public Principal getPeerPrincipal() throws SSLPeerUnverifiedException {
        return null;
    }

    @Override
    public Principal getLocalPrincipal() {
        return null;
    }

    @Override
    public String getCipherSuite() {
        return tlsCipherSuite.name;
    }

    @Override
    public String getProtocol() {
        return protocolVersion.name;
    }

    @Override
    public String getPeerHost() {
        return peerHost;
    }

    @Override
    public int getPeerPort() {
        return peerPort;
    }

    @Override
    public int getPacketBufferSize() {
        //todo
        throw new UnsupportedOperationException();
    }

    @Override
    public int getApplicationBufferSize() {
        //todo
        throw new UnsupportedOperationException();
    }

    @Override
    public ExtendedSSLSession toExtendedSSLSession() {

        return new ExtendedSSLSession() {
            @Override
            public String[] getLocalSupportedSignatureAlgorithms() {
                return GMKaiSSLSession.this.getLocalSupportedSignatureAlgorithms();
            }

            @Override
            public String[] getPeerSupportedSignatureAlgorithms() {
                return GMKaiSSLSession.this.getPeerSupportedSignatureAlgorithms();
            }

            @Override
            public byte[] getId() {
                return GMKaiSSLSession.this.getId();
            }

            @Override
            public SSLSessionContext getSessionContext() {
                return GMKaiSSLSession.this.getSessionContext();
            }

            @Override
            public long getCreationTime() {
                return GMKaiSSLSession.this.getCreationTime();
            }

            @Override
            public long getLastAccessedTime() {
                return GMKaiSSLSession.this.getLastAccessedTime();
            }

            @Override
            public void invalidate() {
                GMKaiSSLSession.this.invalidate();
            }

            @Override
            public boolean isValid() {
                return GMKaiSSLSession.this.isValid();
            }

            @Override
            public void putValue(String s, Object o) {
                GMKaiSSLSession.this.putValue(s, o);
            }

            @Override
            public Object getValue(String s) {
                return GMKaiSSLSession.this.getValue(s);
            }

            @Override
            public void removeValue(String s) {
                GMKaiSSLSession.this.removeValue(s);
            }

            @Override
            public String[] getValueNames() {
                return GMKaiSSLSession.this.getValueNames();
            }

            @Override
            public Certificate[] getPeerCertificates() throws SSLPeerUnverifiedException {
                return GMKaiSSLSession.this.getPeerCertificates();
            }

            @Override
            public Certificate[] getLocalCertificates() {
                return GMKaiSSLSession.this.getLocalCertificates();
            }

            @Override
            public X509Certificate[] getPeerCertificateChain() throws SSLPeerUnverifiedException {
                return GMKaiSSLSession.this.getPeerCertificateChain();
            }

            @Override
            public Principal getPeerPrincipal() throws SSLPeerUnverifiedException {
                return GMKaiSSLSession.this.getPeerPrincipal();
            }

            @Override
            public Principal getLocalPrincipal() {
                return GMKaiSSLSession.this.getLocalPrincipal();
            }

            @Override
            public String getCipherSuite() {
                return GMKaiSSLSession.this.getCipherSuite();
            }

            @Override
            public String getProtocol() {
                return GMKaiSSLSession.this.getProtocol();
            }

            @Override
            public String getPeerHost() {
                return GMKaiSSLSession.this.getPeerHost();
            }

            @Override
            public int getPeerPort() {
                return GMKaiSSLSession.this.getPeerPort();
            }

            @Override
            public int getPacketBufferSize() {
                return GMKaiSSLSession.this.getPacketBufferSize();
            }

            @Override
            public int getApplicationBufferSize() {
                return GMKaiSSLSession.this.getApplicationBufferSize();
            }
        };
    }


}
