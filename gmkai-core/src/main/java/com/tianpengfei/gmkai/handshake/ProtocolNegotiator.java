package com.tianpengfei.gmkai.handshake;


import com.tianpengfei.gmkai.TransportContext;
import com.tianpengfei.gmkai.record.Plaintext;
import com.tianpengfei.gmkai.util.ByteBuffers;

import javax.net.ssl.SSLException;
import java.io.IOException;
import java.nio.ByteBuffer;

/**
 * 用于协商协议和加密套件
 */
public class ProtocolNegotiator {


    public void kickstart(TransportContext tc, HandshakeContext handshakeContext) throws IOException {

        if (handshakeContext.sslParameters.isClientMode()) {

            HandshakeMessage handshakeMessage =
                    ClientHello.handshakeProducer.produce(handshakeContext);

            handshakeContext.writeHandshakeMessage(handshakeMessage);

            Plaintext plaintext = tc.readHandshakeRecord();

            ByteBuffer message = ByteBuffer.wrap(plaintext.fragment.clone());


            SSLHandshakeType sht = SSLHandshakeType.valueOf(message.get());

            if (sht == SSLHandshakeType.SERVER_HELLO) {
                int messageLength = ByteBuffers.getInt24(message);

                ServerHello.handshakeConsumer.consume(handshakeContext, message);
                //消耗成功后，就根据协商的参数就开始组装后面的协议。
                packageHandshake(handshakeContext);

                handshakeContext.switch2read();
                handshakeContext.handshakeHash.update(plaintext.fragment.clone());


            } else {
                System.out.println(sht.name);
                throw new SSLException("");
            }

        } else {
            //TLS1.2 服务端在建立连接的情况下可以发起重新握手，消息类型为 Hello Request
            //在没有建立连接的情况下直接进行信息的读取

            Plaintext plaintext = tc.readHandshakeRecord();

            ByteBuffer message = ByteBuffer.wrap(plaintext.fragment);


            SSLHandshakeType sht = SSLHandshakeType.valueOf(message.get());

            if (sht == SSLHandshakeType.CLIENT_HELLO) {
                int messageLength = ByteBuffers.getInt24(message);
                ClientHello.handshakeConsumer.consume(handshakeContext, message);

                ServerHello.handshakeProducer.produce(handshakeContext);

                //组装协议
                packageHandshake(handshakeContext);

                handshakeContext.switch2write();
            }
        }

    }


    private void packageHandshake(HandshakeContext handshakeContext) {
        if (handshakeContext.sslParameters.isClientMode()) {
            handshakeContext.consumers.add(Certificate.handshakeConsumer);
            handshakeContext.consumers.add(ServerKeyExchange.handshakeConsumer);
            handshakeContext.consumers.add(ServerHelloDone.handshakeConsumer);
            handshakeContext.producers.add(ClientKeyExchange.handshakeProducer);
            handshakeContext.producers.add(Finished.handshakeProducer);
            handshakeContext.consumers.add(Finished.handshakeConsumer);
        } else {
            handshakeContext.producers.add(Certificate.handshakeProducer);
            handshakeContext.producers.add(ServerKeyExchange.handshakeProducer);
            handshakeContext.producers.add(ServerHelloDone.handshakeProducer);
            handshakeContext.consumers.add(ClientKeyExchange.handshakeConsumer);
            handshakeContext.consumers.add(Finished.handshakeConsumer);
            handshakeContext.producers.add(Finished.handshakeProducer);
        }
    }


}