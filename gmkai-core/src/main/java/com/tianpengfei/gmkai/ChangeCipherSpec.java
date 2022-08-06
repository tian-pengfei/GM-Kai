package com.tianpengfei.gmkai;


import javax.net.ssl.SSLException;
import java.io.IOException;
import java.nio.ByteBuffer;

/**
 * 密码变更协议
 * 通知使用新协商的安全参数
 */
public class ChangeCipherSpec {

    static final ChangeCipherSpecConsumer consumer = new ChangeCipherSpecConsumer();

    static final ChangeCipherSpecProducer producer = new ChangeCipherSpecProducer();

    static class ChangeCipherSpecConsumer implements SSLConsumer<TransportContext, ByteBuffer> {

        @Override
        public void consume(TransportContext transportContext, ByteBuffer message) throws IOException {
            message.get();
            transportContext.updateReadKey();
        }
    }


    static class ChangeCipherSpecProducer implements SSLProducer<TransportContext, byte[]> {


        @Override
        public byte[] produce(TransportContext transportContext) throws SSLException, IOException {
            return new byte[]{0x01};
        }

        void finish(TransportContext transportContext) {
            transportContext.updateWriteKey();
        }
    }


}
