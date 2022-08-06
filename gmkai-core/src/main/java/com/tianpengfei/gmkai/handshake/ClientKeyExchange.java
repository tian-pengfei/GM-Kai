package com.tianpengfei.gmkai.handshake;

import com.tianpengfei.gmkai.cipher.Crypto;
import com.tianpengfei.gmkai.util.ByteBuffers;
import com.tianpengfei.gmkai.util.Bytes;
import com.tianpengfei.gmkai.util.bc.SM2Util;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.ShortBufferException;
import javax.net.ssl.SSLException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

public class ClientKeyExchange {

    static final HandshakeProducer handshakeProducer = new ClientKeyExchangeProducer();

    static final HandshakeConsumer handshakeConsumer = new ClientKeyExchangeConsumer();

    static final SSLHandshakeType TYPE = SSLHandshakeType.CLIENT_KEY_EXCHANGE;

    static class ClientKeyExchangeMessage extends HandshakeMessage {

        private final byte[] encodedPreMasterSecret;

        ClientKeyExchangeMessage(byte[] encodedPreMasterSecret) {
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
            ByteBuffers.putBytes16(m, encodedPreMasterSecret);
            return m.array();
        }

        @Override
        int messageLength() {
            return 2 + encodedPreMasterSecret.length;
        }


    }


    static class ClientKeyExchangeConsumer implements HandshakeConsumer {


        @Override
        public void consume(HandshakeContext handshakeContext, ByteBuffer message) throws IOException {

            ClientKeyExchangeMessage clientKeyExchangeMessage = new ClientKeyExchangeMessage(message);

            //解密预主密钥

            try {
                handshakeContext.handshakeSession.setPreSecret(
                        SM2Util.decrypt(
                                (ECPrivateKeyParameters) handshakeContext.contextData.getX509KeyManager().getPrivateKey("enc")
                                , clientKeyExchangeMessage.encodedPreMasterSecret));
            } catch (InvalidCipherTextException e) {
                throw new SSLException("握手失败");
            }
        }

        @Override
        public SSLHandshakeType handshakeType() {
            return TYPE;
        }
    }

    static class ClientKeyExchangeProducer implements HandshakeProducer {


        @Override
        public HandshakeMessage produce(HandshakeContext handshakeContext) throws IOException {

            byte[] preSecret = new byte[48];
            ByteBuffer m = ByteBuffer.wrap(preSecret);
            ByteBuffers.putInt16(m, handshakeContext.negotiatedProtocol.getId());
            SecureRandom secureRandom = new SecureRandom();
            m.put(secureRandom.generateSeed(46));
            byte[] encodedPreSecret;

            BCECPublicKey publicKey = (BCECPublicKey) handshakeContext.
                    handshakeSession.getPeerCertificates()[1].getPublicKey();
            try {
                encodedPreSecret = Crypto.encrypt(publicKey, m.array());
            } catch (InvalidCipherTextException e) {
                throw new SSLException(e.getMessage(), e);
            }

            handshakeContext.handshakeSession.setPreSecret(preSecret);
            byte[] MASTER_SECRET = "master secret".getBytes();

            byte[] seed = Bytes.combine(handshakeContext.clientRandom, handshakeContext.serverRandom);


            try {
                handshakeContext.handshakeSession.setMasterSecret(Crypto.prf(preSecret, MASTER_SECRET, seed, preSecret.length));

            } catch (Exception e) {
                throw new SSLException(e);
            }
            handshakeContext.transportContext.updateSecurityParameters();

            return new ClientKeyExchangeMessage(encodedPreSecret);
        }

        public byte[] getMasterSecret(byte[] preMasterSecret, byte[] clientRandom, byte[] serverRandom) throws IOException {
            byte[] MASTER_SECRET = "master secret".getBytes();
            ByteArrayOutputStream os = new ByteArrayOutputStream();
            os.write(clientRandom);
            os.write(serverRandom);
            byte[] seed = os.toByteArray();
            try {
                return Crypto.prf(preMasterSecret, MASTER_SECRET, seed, preMasterSecret.length);
            } catch (Exception ex) {
                throw new RuntimeException(ex.getMessage(), ex);
            }
        }
    }
}
