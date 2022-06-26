package com.tianpengfei.gmkai;


import javax.net.ssl.SSLContext;
import java.nio.ByteBuffer;
import java.util.List;

/**
 * 握手协议
 */
public class HandshakeContext implements ConnectionContext {


    TransportContext context;

    SSLContext sslContext;

    List<HandshakeConsumer> consumers;

    List<HandshakeProducer> producers;


    public void readHandshakeMessage(ByteBuffer message){

    }

    public void writeHandshakeMessage(){

    }
}
