package net.gmkai;

import java.security.SecureRandom;
import java.util.List;

public interface PreHandshakeContext {

    boolean isClientMode();

    List<TLSCipherSuite> getSupportTLSCipherSuites();

    List<CompressionMethod> getSupportCompressionMethods();

    /**
     * if dont have ,return null
     * only client call
     *
     * @return sessionId
     */
    byte[] getClientReusableSessionId();

    /**
     * 是直接返回SessionContext呢？还是代理一下呢
     *
     * @param sessionId
     * @return session
     */
    GMKaiExtendedSSLSession getSessionById(byte[] sessionId);

    GMKaiExtendedSSLSession createSSLSession(byte[] sessionId, TLSCipherSuite tlsCipherSuite, CompressionMethod compressionMethod);

    SecureRandom getSecureRandom();
}
