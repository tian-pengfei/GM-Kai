package net.gmkai;

import java.util.Arrays;
import java.util.Objects;

public class NegotiationResult {

    public final ProtocolVersion version;

    public final TLSCipherSuite cipherSuite;
    //1->resume
    public final int reuse;

    public final byte[] clientRandom;

    public final byte[] serverRandom;

    public final byte[] sessionId;

    public final long id;

    GMKaiExtendedSSLSession sslSession;

    public NegotiationResult(GMKaiExtendedSSLSession sslSession,
                             ProtocolVersion version,
                             byte[] clientRandom,
                             byte[] serverRandom,
                             byte[] sessionId,
                             TLSCipherSuite cipherSuite,
                             boolean reusable) {
        this.sslSession = sslSession;
        this.version = Objects.requireNonNull(version);
        this.clientRandom = Objects.requireNonNull(clientRandom);
        this.serverRandom = Objects.requireNonNull(serverRandom);
        this.sessionId = Objects.requireNonNull(sessionId);
        this.cipherSuite = Objects.requireNonNull(cipherSuite);
        this.reuse = reusable ? 1 : 0;

        this.id = (long) reuse << 17 | (long) version.id << 16 | cipherSuite.id;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        NegotiationResult that = (NegotiationResult) o;
        return reuse == that.reuse &&
                id == that.id &&
                version == that.version &&
                cipherSuite == that.cipherSuite &&
                Arrays.equals(clientRandom, that.clientRandom) &&
                Arrays.equals(serverRandom, that.serverRandom) &&
                Arrays.equals(sessionId, that.sessionId);
    }

}
