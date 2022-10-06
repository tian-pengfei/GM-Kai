package net.gmkai;

import net.gmkai.event.*;

import javax.net.ssl.SSLSession;
import java.io.IOException;
import java.util.Objects;

class Handshaker implements RecordUpperLayerProtocol {

    private final HashableHandshakeMsgTransport transport;

    private final HandshakeNegotiator negotiator;

    private final HandshakeAssembler assembler = new HandshakeAssembler();

    private final InternalContextData internalContextData;

    private final GMKaiSSLParameters gmKaiSSLParameters;

    private HandshakeContext handshakeContext;

    private final PreHandshakeContext preHandshakeContext;

    private final TLSEventBus tlsEventBus;

    private boolean selfFinished = false;

    private boolean peerFinished = false;

    private NegotiationResult result;

    Handshaker(HandshakeMsgTransport transport,
               PeerInfoProvider peerInfoProvider,
               TLSEventBus tlsEventBus,
               InternalContextData internalContextData,
               GMKaiSSLParameters gmKaiSSLParameters) {

        this.transport = new HashableHandshakeMsgTransport(transport);

        this.tlsEventBus = tlsEventBus;

        this.internalContextData = internalContextData;

        this.negotiator = new HandshakeNegotiator(this.transport);

        this.gmKaiSSLParameters = gmKaiSSLParameters;

        this.preHandshakeContext = new DefaultPreHandshakeContext(
                peerInfoProvider,
                internalContextData,
                gmKaiSSLParameters);

        tlsEventBus.register(new HandshakerListener());


    }


    public void startHandshake() throws IOException {


        result = negotiator.kickStart(preHandshakeContext);

        tlsEventBus.postEvent(new DefiniteProtocolFinishedEvent(result));
        transport.init(internalContextData.getTLSCrypto().createHash(result.cipherSuite.hashAlg));
        this.handshakeContext = new DefaultHandshakeContext(
                result,
                internalContextData,
                gmKaiSSLParameters,
                transport,
                tlsEventBus);
        HandshakeNodes handshakeNodes = assembler.assemble(result);
        HandshakeExecutor executor = new HandshakeExecutor(transport, handshakeContext);
        executor.execute(handshakeNodes);

    }

    public SSLSession getHandshakeSession() {
        if (Objects.isNull(result)) {
            return null;
        }
        return result.sslSession;
    }

    @Override
    public void handleMsgFromOtherProtocol(TLSText tlsText) {
        //todo
        throw new RuntimeException("");
    }

    public boolean getFinished() {
        return peerFinished && selfFinished;
    }

    private class HandshakerListener implements SelfFinishedListener, PeerFinishedListener {


        @Override
        public void handlePeerFinished(PeerFinishedEvent peerFinishedEvent) {
            peerFinished = true;

        }

        @Override
        public void handleSelfFinished(SelfFinishedEvent selfFinishedEvent) {
            selfFinished = true;
        }
    }
}
