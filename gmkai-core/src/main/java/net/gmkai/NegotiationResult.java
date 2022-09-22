package net.gmkai;

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
        this.version = version;
        this.clientRandom = clientRandom;
        this.serverRandom = serverRandom;
        this.sessionId = sessionId;
        this.cipherSuite = cipherSuite;
        this.reuse = reusable ? 1 : 0;
        this.id = (long) reuse << 17 | (long) version.id << 16 | cipherSuite.id;
    }

}
