package com.tianpengfei.gmkai.handshake;

import com.tianpengfei.gmkai.cipher.Crypto;
import com.tianpengfei.gmkai.util.ByteBuffers;
import com.tianpengfei.gmkai.util.Bytes;
import com.tianpengfei.gmkai.util.bc.SM2Util;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
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

    static class ServerKeyExchangeMessage extends HandshakeMessage {

        public byte[] signature;

        ServerKeyExchangeMessage(ByteBuffer message) throws IOException {
            signature = ByteBuffers.getBytes16(message);
        }

        ServerKeyExchangeMessage(byte[] signature) throws IOException {
            this.signature = signature;
        }


        @Override
        SSLHandshakeType getHandshakeType() {
            return TYPE;
        }

        @Override
        byte[] getBytes() throws IOException {
            ByteBuffer m = ByteBuffer.allocate(messageLength());
            ByteBuffers.putBytes16(m, signature);
            return m.array();
        }

        @Override
        int messageLength() {
            return 2 + signature.length;
        }
    }


    static class ServerKeyExchangeProducer implements HandshakeProducer {

        @Override
        public HandshakeMessage produce(HandshakeContext handshakeContext) throws SSLException {

            //验证签名

            // signature privateKey
            BCECPrivateKey privateKey = (BCECPrivateKey) handshakeContext.contextData.getX509KeyManager().getPrivateKey("sig");
            // encryption cert
            X509Certificate encryptionCert = (X509Certificate) handshakeContext.handshakeSession.getLocalCertificates()[1];
            byte[] src;
            try {
                src = Bytes.combine(
                        handshakeContext.clientRandom,
                        handshakeContext.serverRandom,
                        encryptionCert.getEncoded());
            } catch (CertificateEncodingException | IOException e) {
                throw new SSLException(e.getMessage(), e);
            }

            try {
                byte[] signature = SM2Util.sign(privateKey, src);
                return new ServerKeyExchangeMessage(signature);
            } catch (CryptoException | IOException e) {
                throw new SSLException(e.getMessage(), e);
            }


        }
    }

    static class ServerKeyExchangeConsumer implements HandshakeConsumer {

        @Override
        public void consume(HandshakeContext handshakeContext, ByteBuffer message) throws IOException {

            ServerKeyExchangeMessage serverKeyExchangeMessage = new ServerKeyExchangeMessage(message);
            //验证签名

            // signature cert
            X509Certificate signCert = (X509Certificate) handshakeContext.handshakeSession.getPeerCertificates()[0];
            // encryption cert
            X509Certificate encryptionCert = (X509Certificate) handshakeContext.handshakeSession.getPeerCertificates()[1];
            ;

            byte[] src;
            boolean verified = false;
            try {
                byte[] certBytes = encryptionCert.getEncoded();
                src = Bytes.combine(
                        handshakeContext.clientRandom,
                        handshakeContext.serverRandom,
                        Bytes.get3Bytes(certBytes.length), certBytes);
                verified =
                        SM2Util.verify((BCECPublicKey) signCert.getPublicKey(), src, serverKeyExchangeMessage.signature);
            } catch (CertificateEncodingException e) {
                throw new SSLException(e.getMessage(), e);
            }

            if (!verified) {
                throw new SSLException("server key exchange verify fails!");
            }


        }

        @Override
        public SSLHandshakeType handshakeType() {
            return TYPE;
        }
    }
}