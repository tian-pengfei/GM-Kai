package net.gmkai;

public interface ProtocolMatcher {

    HandshakeMsg createClientHello(PreHandshakeContext preHandshakeContext, HandshakeNegotiatorSession handshakeNegotiatorSession);

    HandshakeMsg createServerHello(PreHandshakeContext preHandshakeContext, HandshakeNegotiatorSession handshakeNegotiatorSession);

    boolean consumeClientHello(byte[] clientHello, PreHandshakeContext preHandshakeContext, HandshakeNegotiatorSession handshakeNegotiatorSession);

    boolean consumeServerHello(byte[] serverHello, PreHandshakeContext preHandshakeContext, HandshakeNegotiatorSession handshakeNegotiatorSession);

}
