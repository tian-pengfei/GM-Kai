package net.gmkai;

import com.google.common.collect.ImmutableList;

import javax.net.ssl.SSLException;
import java.io.IOException;
import java.util.List;

public class HandshakeNegotiator {

    private final HandshakeMsgTransport transport;


    private final static List<ProtocolMatcher> matchers = ImmutableList.of(new TLCP11ProtocolMatcher());

    HandshakeNegotiator(HandshakeMsgTransport transport) {
        this.transport = transport;
    }

    public NegotiationResult kickStart(PreHandshakeContext preHandshakeContext) throws IOException {

        if (preHandshakeContext.isClientMode()) {
            return clientKickStart(preHandshakeContext);
        }

        return serverKickStart(preHandshakeContext);
    }

    private NegotiationResult clientKickStart(PreHandshakeContext preHandshakeContext) throws IOException {

        HandshakeNegotiatorSession negotiatorSession = new HandshakeNegotiatorSession();

        ProtocolMatcher matcher = matchers.stream().findFirst().orElseThrow(() -> new SSLException(""));

        HandshakeMsg clientHelloMsg = matcher.createClientHello(preHandshakeContext, negotiatorSession);

        transport.writeHandshakeMsg(clientHelloMsg);

        byte[] body = getServerHelloMsgBody();

        for (ProtocolMatcher expectedMatcher : matchers) {
            HandshakeNegotiatorSession _negotiatorSession = negotiatorSession.clone();

            boolean match = expectedMatcher.consumeServerHello(body, preHandshakeContext, _negotiatorSession);
            if (match) {
                return _negotiatorSession.getNegotiationResult();
            }
        }

        throw new SSLException("");

    }

    private NegotiationResult serverKickStart(PreHandshakeContext preHandshakeContext) throws IOException {

        byte[] body = getClientHelloMsgBody();

        for (ProtocolMatcher expectedMatcher : matchers) {
            HandshakeNegotiatorSession negotiatorSession = new HandshakeNegotiatorSession();

            boolean match = expectedMatcher.consumeClientHello(body, preHandshakeContext, negotiatorSession);

            if (match) {
                HandshakeMsg handshakeMsg = expectedMatcher.createServerHello(preHandshakeContext, negotiatorSession);
                transport.writeHandshakeMsg(handshakeMsg);
                return negotiatorSession.getNegotiationResult();
            }
        }
        throw new SSLException("");
    }


    private byte[] getClientHelloMsgBody() throws IOException {


        HandshakeMsg handshakeMsg = transport.readHandshakeMsg();

        if (handshakeMsg.getHandshakeType() == HandshakeType.CLIENT_HELLO) {
            return handshakeMsg.getBody();
        }
        throw new SSLException("wrong handshake type");
    }

    private byte[] getServerHelloMsgBody() throws IOException {

        HandshakeMsg handshakeMsg = transport.readHandshakeMsg();
        if (handshakeMsg.getHandshakeType() == HandshakeType.SERVER_HELLO) {
            return handshakeMsg.getBody();
        }

        if (handshakeMsg.getHandshakeType() == HandshakeType.HELLO_REQUEST) {
            //todo
        }

        throw new SSLException("wrong handshake type");
    }

}
