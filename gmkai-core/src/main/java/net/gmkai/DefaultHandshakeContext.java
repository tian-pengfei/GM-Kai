package net.gmkai;

import net.gmkai.crypto.KeyExchangeAlg;
import net.gmkai.crypto.TLSCrypto;
import net.gmkai.event.*;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLException;
import java.security.cert.X509Certificate;
import java.util.Objects;


public class DefaultHandshakeContext implements HandshakeContext {

    private final GMKaiExtendedSSLSession sslSession;

    private final InternalContextData internalContextData;

    private final GMKaiSSLParameters gmKaiSSLParameters;

    private final NegotiationResult negotiationResult;

    private byte[] preMasterSecret;

    private final TransportHasher transportHasher;

    private final TLSEventBus tlsEventBus;

    private TLCPX509Possession possession;

    public DefaultHandshakeContext(NegotiationResult negotiationResult,
                                   InternalContextData internalContextData,
                                   GMKaiSSLParameters gmKaiSSLParameters,
                                   TransportHasher transportHasher,
                                   TLSEventBus tlsEventBus) {

        this.sslSession = negotiationResult.sslSession;

        this.negotiationResult = negotiationResult;

        this.internalContextData = internalContextData;

        this.gmKaiSSLParameters = gmKaiSSLParameters;

        this.transportHasher = transportHasher;

        this.tlsEventBus = tlsEventBus;


    }

    @Override
    public boolean isClientMode() {
        return gmKaiSSLParameters.getUseClientMode();
    }

    @Override
    public InternalX509TrustManager getX509TrustManager() {
        return internalContextData.getTrustManager();
    }

    @Override
    public KeyManager getKeyManager() {
        return internalContextData.getKeyManager();
    }

    @Override
    public void setPeerCertChain(X509Certificate[] chain) {
        sslSession.putPeerCertificate(chain);
    }

    @Override
    public void setTLCPX509Possession(TLCPX509Possession possession) {
        this.possession = possession;
        sslSession.putLocalCertificate(possession.getChain());
    }

    @Override
    public TLCPX509Possession getTLCPX509Possession() {
        if (Objects.isNull(possession)) {
            throw new IllegalStateException("possession have not been initialized");
        }
        return possession;
    }

    @Override
    public X509Certificate[] getPeerCertChain() throws SSLException {
        return (X509Certificate[]) sslSession.getPeerCertificates();
    }

    @Override
    public X509Certificate[] getLocalCertChain() {

        return (X509Certificate[]) sslSession.getLocalCertificates();
    }

    @Override
    public TLSCipherSuite getCurrentCipherSuite() {
        return negotiationResult.cipherSuite;
    }

    @Override
    public ProtocolVersion getCurrentProtocol() {
        return negotiationResult.version;
    }

    @Override
    public byte[] getClientRandom() {
        return negotiationResult.clientRandom;
    }

    @Override
    public byte[] getServerRandom() {
        return negotiationResult.serverRandom;
    }

    @Override
    public TLSCrypto getTLSCrypto() {
        return internalContextData.getTLSCrypto();
    }

    @Override
    public void setPreMasterSecret(byte[] preMasterSecret) {
        this.preMasterSecret = preMasterSecret;
    }

    @Override
    public byte[] getPreMasterSecret() {
        return preMasterSecret;
    }

    @Override
    public void setMasterSecret(byte[] masterSecret) {
        sslSession.putMasterSecret(masterSecret);
    }

    @Override
    public byte[] getMasterSecret() {
        return sslSession.getMasterSecret();
    }

    @Override
    public TransportHasher getTransportHasher() {
        return transportHasher;
    }

    @Override
    public boolean isNeedAuthClient() {
        return gmKaiSSLParameters.getNeedClientAuth() ||
                isNeedAuthClient(getCurrentCipherSuite());
    }

    private boolean isNeedAuthClient(TLSCipherSuite tlsCipherSuite) {

        return tlsCipherSuite.keyExchangeAlg == KeyExchangeAlg.K_ECDHE;
    }

    private SecurityParameters getSecurityParameters() {

        return SecurityParameters.SecurityParametersBuilder.aSecurityParameters()
                .withMasterSecret(getMasterSecret())
                .withMacAlg(negotiationResult.cipherSuite.macAlg)
                .withBulkCipherAlg(negotiationResult.cipherSuite.bulkCipherAlg)
                .withServerRandom(getServerRandom())
                .withClientRandom(getClientRandom())
                .withConnectionEnd(gmKaiSSLParameters.getUseClientMode() ?
                        ConnectionEnd.CLIENT : ConnectionEnd.SERVER)
                .withRecordIvLength(negotiationResult.cipherSuite.bulkCipherAlg.ivLength)
                .build();
    }

    @Override
    public void notifySelfFinished() {
        tlsEventBus.postEvent(new SelfFinishedEvent());
    }

    @Override
    public void notifyPeerFinished() {
        tlsEventBus.postEvent(new PeerFinishedEvent());
    }

    @Override
    public void changeWriteCipherSpec() {

        tlsEventBus.postEvent(new ChangeWriteCipherSpecEvent());
    }

    @Override
    public void generateSecurityParameters() {
        tlsEventBus.postEvent(new GenerateSecurityParametersFinishedEvent(getSecurityParameters()));
    }
}
