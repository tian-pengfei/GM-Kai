package net.gmkai;

import com.google.common.collect.ImmutableList;

import java.security.SecureRandom;
import java.util.List;

public class DefaultPreHandshakeContext implements PreHandshakeContext {

    private final PeerInfoProvider peerInfoProvider;

    private final InternalContextData internalContextData;

    private final GMKaiSSLParameters gmKaiSSLParameters;

    public DefaultPreHandshakeContext(PeerInfoProvider peerInfoProvider,
                                      InternalContextData internalContextData,
                                      GMKaiSSLParameters gmKaiSSLParameters) {

        this.internalContextData = internalContextData;
        this.peerInfoProvider = peerInfoProvider;
        this.gmKaiSSLParameters = gmKaiSSLParameters;
    }

    @Override
    public boolean isClientMode() {
        return gmKaiSSLParameters.getUseClientMode();
    }

    @Override
    public List<TLSCipherSuite> getSupportTLSCipherSuites() {
        return gmKaiSSLParameters.getSupportedCipherSuites();
    }

    @Override
    public List<CompressionMethod> getSupportCompressionMethods() {
        return ImmutableList.of(CompressionMethod.NULL);
    }

    @Override
    public byte[] getClientReusableSessionId() {
        // todo get reusable old session id from SSLSessionContext
        return null;
    }

    @Override
    public GMKaiExtendedSSLSession getSessionById(byte[] sessionId) {
        // todo get old session from SSLSessionContext
        return null;
    }

    @Override
    public GMKaiExtendedSSLSession createSSLSession(byte[] sessionId, TLSCipherSuite tlsCipherSuite, CompressionMethod compressionMethod) {

        return new GMKaiSSLSession(
                sessionId,
                peerInfoProvider.getHostname(),
                peerInfoProvider.getPort(),
                tlsCipherSuite,
                compressionMethod);
    }

    @Override
    public SecureRandom getSecureRandom() {
        return internalContextData.getSecureRandom();
    }
}
