package com.tianpengfei.gmkai.handshake;

import com.tianpengfei.gmkai.util.ByteBuffers;
import com.tianpengfei.gmkai.util.bc.SM2Util;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;

import javax.net.ssl.SSLException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.SecureRandom;

public class ClientKeyExchange {

    static final HandshakeProducer handshakeProducer = new ClientKeyExchangeProducer();

    static final HandshakeConsumer handshakeConsumer = new ClientKeyExchangeConsumer();

    static final SSLHandshakeType TYPE = SSLHandshakeType.CLIENT_KEY_EXCHANGE;

    static class ClientKeyExchangeMessage extends HandshakeMessage {

        private final byte[] encodedPreMasterSecret;

        ClientKeyExchangeMessage(byte[] encodedPreMasterSecret){
            this.encodedPreMasterSecret = encodedPreMasterSecret;
        }
        ClientKeyExchangeMessage(ByteBuffer m) throws IOException {
            this.encodedPreMasterSecret = ByteBuffers.getBytes16(m);
        }
        @Override
        SSLHandshakeType getHandshakeType() {
            return TYPE;
        }

        @Override
        byte[] getBytes() throws IOException {

            ByteBuffer m = ByteBuffer.allocate(messageLength());
            ByteBuffers.putBytes16(m,encodedPreMasterSecret);
            return m.array();
        }

        @Override
        int messageLength() {
            return 2+encodedPreMasterSecret.length;
        }


    }


    static class  ClientKeyExchangeConsumer implements HandshakeConsumer{


        @Override
        public void consume(HandshakeContext context, ByteBuffer message) throws IOException {

            ClientKeyExchangeMessage clientKeyExchangeMessage = new ClientKeyExchangeMessage(message);

            //解密预主密钥
        }

        @Override
        public SSLHandshakeType handshakeType() {
            return TYPE;
        }
    }

    static class  ClientKeyExchangeProducer implements HandshakeProducer{


        @Override
        public HandshakeMessage produce(HandshakeContext handshakeContext) throws IOException {

            byte[] preSecret = new byte[48];
            ByteBuffer m = ByteBuffer.wrap(preSecret);
            ByteBuffers.putInt16(m,handshakeContext.negotiatedProtocol.getId());
            SecureRandom secureRandom = new SecureRandom();
            m.put(secureRandom.generateSeed(46));
            byte[] encodedPreSecret;

            BCECPublicKey publicKey = (BCECPublicKey) handshakeContext.peerCerts[1].getPublicKey();
            try {
                 encodedPreSecret = SM2Util.encrypt(publicKey,m.array());
            } catch (InvalidCipherTextException e) {
                throw new SSLException("");
            }

            return new ClientKeyExchangeMessage(encodedPreSecret);
        }
    }
}
