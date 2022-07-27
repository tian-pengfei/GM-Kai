package com.tianpengfei.gmkai.handshake;

import com.tianpengfei.gmkai.util.ByteBuffers;
import com.tianpengfei.gmkai.util.Bytes;
import com.tianpengfei.gmkai.util.bc.SM2Util;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;

import javax.net.ssl.SSLException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

public class ServerKeyExchange {


        static final HandshakeProducer handshakeProducer = new ServerKeyExchangeProducer();

        static final HandshakeConsumer handshakeConsumer = new ServerKeyExchangeConsumer();

        static final SSLHandshakeType TYPE = SSLHandshakeType.SERVER_KEY_EXCHANGE;

        static class ServerKeyExchangeMessage extends HandshakeMessage{

            public byte[] signature;

            ServerKeyExchangeMessage(ByteBuffer message) throws IOException {
                signature = ByteBuffers.getBytes16(message);
            }
            @Override
            SSLHandshakeType getHandshakeType() {
                return TYPE;
            }

            @Override
            byte[] getBytes() throws IOException {
                ByteBuffer m = ByteBuffer.allocate(messageLength());
                ByteBuffers.putBytes16(m,signature);
                return m.array();
            }

            @Override
            int messageLength() {
                return 2+signature.length;
            }
        }


        static  class  ServerKeyExchangeProducer implements  HandshakeProducer{

            @Override
            public HandshakeMessage produce(HandshakeContext handshakeContext) throws SSLException {

                //验证签名

                // signature cert
                X509Certificate signCert = handshakeContext.peerCerts[0];
                // encryption cert
                X509Certificate encryptionCert = handshakeContext.peerCerts[1];
                byte[] src;
                try {
                    src = Bytes.combine(
                            handshakeContext.clientRandom,
                            handshakeContext.serverRandom,
                            encryptionCert.getEncoded());
                } catch (CertificateEncodingException | IOException e) {
                    throw new SSLException("");
                }
//                byte[] signature  = SM2Util.sign()
                return null;

            }
        }

    static class ServerKeyExchangeConsumer implements HandshakeConsumer{

        @Override
        public void consume(HandshakeContext handshakeContext, ByteBuffer message) throws IOException {

            ServerKeyExchangeMessage serverKeyExchangeMessage = new ServerKeyExchangeMessage(message);
            //验证签名

            // signature cert
            X509Certificate signCert = handshakeContext.peerCerts[0];
            // encryption cert
            X509Certificate encryptionCert = handshakeContext.peerCerts[1];
            byte[] src;
            try {
                src = Bytes.combine(
                        handshakeContext.clientRandom,
                        handshakeContext.serverRandom,
                        encryptionCert.getEncoded());
            } catch (CertificateEncodingException e) {
                throw new SSLException("");
            }


            SM2Util.verify((BCECPublicKey) signCert.getPublicKey(),src,serverKeyExchangeMessage.signature );

        }

        @Override
        public SSLHandshakeType handshakeType() {
            return TYPE;
        }
    }
}