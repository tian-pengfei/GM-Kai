package net.gmkai;

import java.util.Objects;

public class NegotiationResult {

    final ProtocolVersion version;

    final TLSCipherSuite cipherSuite;
    //1->resume
    final int reuse;

    final byte[] clientRandom;

    final byte[] serverRandom;

    final byte[] sessionId;

    final long id;

    public NegotiationResult(ProtocolVersion version, byte[] clientRandom, byte[] serverRandom, byte[] sessionId, TLSCipherSuite cipherSuite, boolean reusable) {
        this.version = Objects.requireNonNull(version);
        this.clientRandom = Objects.requireNonNull(clientRandom);
        this.serverRandom = Objects.requireNonNull(serverRandom);
        this.sessionId = Objects.requireNonNull(sessionId);
        this.cipherSuite = Objects.requireNonNull(cipherSuite);
        this.reuse = reusable ? 1 : 0;

        this.id = (long) reuse << 17 | (long) version.id << 16 | cipherSuite.id;
    }


}
