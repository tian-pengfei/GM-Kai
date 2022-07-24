package com.tianpengfei.gmkai.handshake;


import com.google.common.eventbus.Subscribe;
import com.tianpengfei.gmkai.*;
import com.tianpengfei.gmkai.record.ContentType;
import com.tianpengfei.gmkai.record.Plaintext;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.List;

/**
 * 握手协议
 */
public class HandshakeContext implements ConnectionContext {


    TransportContext context;

    SSLContext sslContext;

    // consolidated parameters
    final List<ProtocolVersion> activeProtocols;

    final List<CipherSuite> activeCipherSuites;

    List<HandshakeConsumer> consumers;

    List<HandshakeProducer> producers;

    ProtocolNegotiator protocolNegotiator;

    GMSSLSession handshakeSession;

    byte[] clientRandom;

    byte[] serverRandom;

    ProtocolVersion negotiatedProtocol;

    CipherSuite negotiatedCipherSuite;

    ByteBuffer currentHandshakeMessage;


    HandshakeContext() {
        this.activeProtocols = Arrays.asList(ProtocolVersion.GM_PROTOCOLS);
        this.activeCipherSuites = Arrays.asList(CipherSuite.values());
        protocolNegotiator = new ProtocolNegotiator(context);
    }


    @Subscribe
    public void consume(HandshakeConsumeEvent hce) throws IOException {
        if (this.currentHandshakeMessage == null) {
            this.currentHandshakeMessage = readHandshakeMessage();
        }

        consumers.remove(0).consume(this, currentHandshakeMessage);
    }

    public void kickstart(TransportContext tc) {
        protocolNegotiator.kickstart(tc);
    }

    @Subscribe
    public void produce(HandshakeProduceEvent hpe) {
        HandshakeMessage sendHandshakeMessage = producers.remove(0).produce(this);
        writeHandshakeMessage(sendHandshakeMessage);

    }

    @Subscribe
    public void finish(HandshakeFinishEvent hfe) {

    }

    private ByteBuffer readHandshakeMessage() {

        Plaintext plaintext = context.readRecord();
        return ByteBuffer.wrap(plaintext.fragment);
    }

    private void writeHandshakeMessage(HandshakeMessage message) {


        context.writeRecord(ContentType.APPLICATION_DATA, null);
    }
}
