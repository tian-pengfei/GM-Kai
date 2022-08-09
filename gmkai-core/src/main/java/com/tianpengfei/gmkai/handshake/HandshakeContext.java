package com.tianpengfei.gmkai.handshake;


import com.google.common.collect.Lists;
import com.tianpengfei.gmkai.*;
import com.tianpengfei.gmkai.record.Plaintext;
import com.tianpengfei.gmkai.record.SecurityParameters;
import com.tianpengfei.gmkai.util.ByteBuffers;
import org.bouncycastle.tls.ConnectionEnd;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.List;

/**
 * 握手协议
 */
public class HandshakeContext implements ConnectionContext {


    TransportContext transportContext;

    GMSSLParameters sslParameters;

    ProtocolVersion maxProtocolVersion = ProtocolVersion.GMSSL11;

    final List<ProtocolVersion> activeProtocols;

    final List<CipherSuite> activeCipherSuites;

    List<HandshakeConsumer> consumers = Lists.newArrayList();

    List<HandshakeProducer> producers = Lists.newArrayList();

    ProtocolNegotiator protocolNegotiator;

    GMSSLSession handshakeSession;

    byte[] clientRandom;

    byte[] serverRandom;

    boolean isProtocolNegotiated = false;

    ProtocolVersion negotiatedProtocol = ProtocolVersion.GMSSL11;

    CipherSuite negotiatedCipherSuite;

    boolean isNegotiated = false;

    boolean isRead = false;

    boolean isSendFinish = false;

    boolean isRecvFinish = false;

    HandshakeHash handshakeHash = new HandshakeHash();

    public HandshakeContext(TransportContext transportContext, GMSSLParameters sslParameters) {
        this.activeProtocols = Arrays.asList(ProtocolVersion.GM_PROTOCOLS);
        this.activeCipherSuites = Arrays.asList(CipherSuite.values());
        this.protocolNegotiator = new ProtocolNegotiator();
        this.sslParameters = sslParameters;
        this.transportContext = transportContext;
    }


    //服务端怎么接收消息呢？

    public void startHandshake(TransportContext tc) throws IOException {

        protocolNegotiator.kickstart(tc, this);

        while (!isNegotiated) {
            if (isRead) {
                readHandshakeMessage();
            } else {
                writeHandshakeMessage();
            }
        }
    }


    private void readHandshakeMessage() throws IOException {

        Plaintext plaintext = transportContext.readHandshakeRecord();

        ByteBuffer hm = ByteBuffer.wrap(plaintext.fragment);

        byte[] message = hm.array().clone();

        SSLHandshakeType sht = SSLHandshakeType.valueOf(hm.get());
        int messageLength = ByteBuffers.getInt24(hm);
        if (sht == SSLHandshakeType.HELLO_REQUEST) {
            System.out.println(SSLHandshakeType.HELLO_REQUEST.name);
            return;
        }
        HandshakeConsumer hc = consumers.remove(0);
        while (!hc.isNeed(this)) {
            hc = consumers.remove(0);
        }

        if (sht == hc.handshakeType()) {
            hc.consume(this, hm);

            if (sht == SSLHandshakeType.CLIENT_HELLO) {
                handshakeHash.reset();
            }
            handshakeHash.update(message);
        } else {
            System.out.println("期望消息：" + hc.handshakeType().name);
            System.out.println("接收到的消息" + sht.name);
        }
    }

    private void writeHandshakeMessage() throws IOException {

        HandshakeProducer handshakeProducer = producers.remove(0);

        while (!handshakeProducer.isNeed(this)) {
            handshakeProducer = producers.remove(0);
        }

        HandshakeMessage hm = handshakeProducer.produce(this);

        writeHandshakeMessage(hm);

        handshakeProducer.finished(this);

    }

    void writeHandshakeMessage(HandshakeMessage hm) throws IOException {

        ByteBuffer m = ByteBuffer.allocate(1 + 3 + hm.messageLength());
        m.put(hm.getHandshakeType().id);
        ByteBuffers.putBytes24(m, hm.getBytes());
        m.flip();
        byte[] message = m.array().clone();
        transportContext.writeHandshakeRecord(m);
//        System.out.println("发送" + hm.getHandshakeType().name + "消息");
        if (hm.getHandshakeType() == SSLHandshakeType.CLIENT_HELLO) {
            handshakeHash.reset();
        }
        handshakeHash.update(message);

    }

    /**
     * 握手中读的任务暂时结束，开启写任务。
     */

    void switch2write() {
        isRead = false;
    }

    /**
     * 握手中写的任务暂时结束，开启都任务。
     * 比如TLS握手过程中发送一个ServerHelloDone消息表明写任务结束，开启读任务。
     * 发送Finished但是没有收到对方的FINISHED任务，表明写任务结束开启读任务
     **/
    void switch2read() {
        isRead = true;
    }

    /**
     * 握手结束
     * 比如TLS握手过程中 收到一个FINISHED 消息并且发送一个FINISHED这两个条件同时满足的话，表明握手结束。
     */
    void handshakeFinished() {
        isNegotiated = true;
        transportContext.setNegotiated(isNegotiated);
    }

    public GMSSLSession getHandshakeSession() {
        return handshakeSession;
    }


    public SecurityParameters getSecurityParams() {

        return new SecurityParameters(sslParameters.isClientMode() ? ConnectionEnd.client : ConnectionEnd.server,
                clientRandom, serverRandom, handshakeSession.getMasterSecret());

    }

    public GMSSLContextData getContextData() {
        return transportContext.getContextData();
    }
}
