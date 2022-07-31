package com.tianpengfei.gmkai.handshake;


import com.google.common.eventbus.Subscribe;
import com.tianpengfei.gmkai.*;
import com.tianpengfei.gmkai.record.ContentType;
import com.tianpengfei.gmkai.record.Plaintext;
import com.tianpengfei.gmkai.util.ByteBuffers;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

/**
 * 握手协议
 */
public class HandshakeContext implements ConnectionContext {


    TransportContext transportContext;

    GMContextData contextData;

    GMSSLParameters gmsslParameters;

    ProtocolVersion maxProtocolVersion = ProtocolVersion.GMSSL11;

    // consolidated parameters
    final List<ProtocolVersion> activeProtocols;

    final List<CipherSuite> activeCipherSuites;

    List<HandshakeConsumer> consumers;

    List<HandshakeProducer> producers;

    ProtocolNegotiator protocolNegotiator;

    GMSSLSession handshakeSession;

    byte[] clientRandom;

    byte[] serverRandom;

    byte[] preMasterSecret;

    boolean isProtocolNegotiated = false;

    ProtocolVersion negotiatedProtocol;

    CipherSuite negotiatedCipherSuite;

    boolean isNegotiated = false;

    boolean isRead = false;

    X509Certificate[] peerCerts;

    HandshakeContext() {
        this.activeProtocols = Arrays.asList(ProtocolVersion.GM_PROTOCOLS);
        this.activeCipherSuites = Arrays.asList(CipherSuite.values());
        this.protocolNegotiator = new ProtocolNegotiator();
    }


    //服务端怎么接收消息呢？

    public void kickstart(TransportContext tc) throws IOException {

        protocolNegotiator.kickstart(tc, this);

        while (!isNegotiated) {
            if (isRead) {
                readHandshakeMessage();
            } else {
                writeHandshakeMessage();
            }
        }
    }


    @Subscribe
    public void finish(HandshakeFinishEvent hfe) {

    }

    private void readHandshakeMessage() throws IOException {

        Plaintext plaintext = transportContext.readRecord();

        ByteBuffer hm = ByteBuffer.wrap(plaintext.fragment);

        SSLHandshakeType sht = SSLHandshakeType.valueOf(hm.get());

        HandshakeConsumer hc = consumers.remove(0);
        while (hc.isNeed(this)) {
            hc = consumers.remove(0);
        }

        if (sht == hc.handshakeType()) {
            hc.consume(this, hm);
        }
        consumers.remove(0).consume(this, hm);

    }

    private void writeHandshakeMessage() throws IOException {

        HandshakeProducer handshakeProducer = producers.remove(0);

        while (!handshakeProducer.isNeed(this)) {
            handshakeProducer = producers.remove(0);
        }

        HandshakeMessage hm = handshakeProducer.produce(this);

        ByteBuffer m = ByteBuffer.allocate(1 + 3 + hm.messageLength());
        m.put(hm.getHandshakeType().id);
        ByteBuffers.putBytes24(m, hm.getBytes());
        transportContext.writeRecord(ContentType.APPLICATION_DATA, m.array());

        handshakeProducer.finished();


    }

    /**
     * 握手中读的任务暂时结束，开启写任务。
     */

    void readFinished() {

        isRead = false;
    }

    /**
     * 握手中写的任务暂时结束，开启都任务。
     * 比如TLS握手过程中发送一个ServerHelloDone消息表明写任务结束，开启读任务。
     * 发送Finished但是没有收到对方的FINISHED任务，表明写任务结束开启读任务
     **/
    void writeFinished() {
        isRead = true;
    }

    /**
     * 握手结束
     * 比如TLS握手过程中 收到一个FINISHED 消息并且发送一个FINISHED这两个条件同时满足的话，表明握手结束。
     */
    void handshakeFinished() {
        isNegotiated = true;
    }

}
