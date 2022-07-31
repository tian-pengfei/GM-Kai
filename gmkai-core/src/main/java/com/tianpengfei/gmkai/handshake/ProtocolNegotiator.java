package com.tianpengfei.gmkai.handshake;


import com.tianpengfei.gmkai.TransportContext;
import com.tianpengfei.gmkai.record.ContentType;
import com.tianpengfei.gmkai.record.Plaintext;

import javax.net.ssl.SSLException;
import java.io.IOException;
import java.nio.ByteBuffer;

/**
 * 用于协商协议和加密套件
 */
public class ProtocolNegotiator {


    public void kickstart(TransportContext tc, HandshakeContext handshakeContext) throws IOException {

        if (handshakeContext.sslConfiguration.getUseClientMode()) {

            ClientHello.handshakeProducer.produce(handshakeContext);

            Plaintext plaintext = tc.readRecord();

            ByteBuffer message = ByteBuffer.wrap(plaintext.fragment);

            if (plaintext.getContentType() == ContentType.HANDSHAKE) {

                SSLHandshakeType sht = SSLHandshakeType.valueOf(message.get());

                if (sht == SSLHandshakeType.SERVER_HELLO) {

                    ServerHello.handshakeConsumer.consume(handshakeContext, message);
                    //消耗成功后，就根据协商的参数就开始组装后面的协议。
                    packageHandshake(handshakeContext);

                } else {
                    throw new SSLException("");
                }

            } else if (plaintext.getContentType() == ContentType.ALERT) {
                throw new SSLException("");
            } else if (plaintext.getContentType() == ContentType.APPLICATION_DATA) {
                throw new SSLException("");
            } else {
                throw new SSLException("");
            }


        } else {
            //TLS1.2 服务端在建立连接的情况下可以发起重新握手，消息类型为 Hello Request
            //在没有建立连接的情况下直接进行信息的读取

            Plaintext plaintext = tc.readRecord();

            ByteBuffer message = ByteBuffer.wrap(plaintext.fragment);

            if (plaintext.getContentType() == ContentType.HANDSHAKE) {

                SSLHandshakeType sht = SSLHandshakeType.valueOf(message.get());

                if (sht == SSLHandshakeType.CLIENT_HELLO) {

                    ClientHello.handshakeConsumer.consume(handshakeContext, message);

                    ServerHello.handshakeProducer.produce(handshakeContext);

                    //组装协议
                    packageHandshake(handshakeContext);

                }
            }
        }

    }


    private void packageHandshake(HandshakeContext handshakeContext) {


    }


}