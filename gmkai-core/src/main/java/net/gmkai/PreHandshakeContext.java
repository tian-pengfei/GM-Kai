package net.gmkai;

import java.security.SecureRandom;
import java.util.List;

public interface PreHandshakeContext {

    boolean isClientMode();

    List<TLSCipherSuite> getSupportTLSCipherSuites();

    List<CompressionMethod> getSupportCompressionMethods();

    /**
     * if dont have ,return null
     *
     * @return sessionId
     */
    byte[] getReusableSessionId();

    SecureRandom getSecureRandom();
}
