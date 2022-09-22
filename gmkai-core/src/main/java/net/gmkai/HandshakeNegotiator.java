package net.gmkai;

import com.google.common.collect.ImmutableList;
import net.gmkai.util.ByteBuffers;

import javax.net.ssl.SSLException;
import java.io.IOException;
import java.nio.ByteBuffer;
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

        transport.writeHandshakeMsg(clientHelloMsg.getProtocolFormat());

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
                transport.writeHandshakeMsg(handshakeMsg.getProtocolFormat());
                return negotiatorSession.getNegotiationResult();
            }
        }
        throw new SSLException("");
    }


    private byte[] getClientHelloMsgBody() throws IOException {


        TLSText tlsText = transport.readHandshakeMsg();
        ByteBuffer byteBuffer = ByteBuffer.wrap(tlsText.fragment);
        HandshakeType handshakeType = HandshakeType.valueOf(byteBuffer.get()).
                orElseThrow(()->new SSLException("unrecognized handshake type"));

        if(handshakeType==HandshakeType.CLIENT_HELLO){
            return ByteBuffers.getBytes24(byteBuffer);
        }
        throw  new SSLException("wrong handshake type");
    }

    private byte[] getServerHelloMsgBody() throws IOException {

        GenericHandshakeMsg handshakeMsg = getHandshakeMsg();
        if(handshakeMsg.getHandshakeType()==HandshakeType.SERVER_HELLO){
            return handshakeMsg.getBody();
        }

        if(handshakeMsg.getHandshakeType()==HandshakeType.HELLO_REQUEST){
            //todo
        }

        throw  new SSLException("wrong handshake type");
    }


    private GenericHandshakeMsg getHandshakeMsg() throws IOException {

        TLSText tlsText = transport.readHandshakeMsg();

        return GenericHandshakeMsg.getInstance(tlsText.fragment);
    }
}
