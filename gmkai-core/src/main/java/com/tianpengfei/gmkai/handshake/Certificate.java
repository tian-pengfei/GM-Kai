package com.tianpengfei.gmkai.handshake;

import com.tianpengfei.gmkai.util.ByteBuffers;

import javax.net.ssl.SSLException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

public class Certificate {

    static final HandshakeProducer handshakeProducer = new CertificateProducer();

    static final HandshakeConsumer handshakeConsumer = new CertificateConsumer();

    static final SSLHandshakeType TYPE = SSLHandshakeType.CERTIFICATE;

    static class CertificateMessage extends HandshakeMessage {

        final List<byte[]> encodedCertChain;

        CertificateMessage(X509Certificate[] certChain) throws SSLException {
            List<byte[]> encodedCerts = new ArrayList<>(certChain.length);
            for (X509Certificate cert : certChain) {

                try {
                    encodedCerts.add(cert.getEncoded());
                } catch (CertificateEncodingException e) {
                    throw new SSLException(e.getMessage());
                }
            }
            this.encodedCertChain = encodedCerts;
        }

        CertificateMessage(ByteBuffer m) throws IOException {

            int len = ByteBuffers.getInt24(m);

            if (len > 0) {
                List<byte[]> encodedCerts = new LinkedList<>();
                while (len > 0) {
                    byte[] encodedCert = ByteBuffers.getBytes24(m);
                    len -= (3 + encodedCert.length);
                    encodedCerts.add(encodedCert);
                }
                this.encodedCertChain = encodedCerts;

            } else {
                this.encodedCertChain = Collections.emptyList();
            }
        }

        @Override
        SSLHandshakeType getHandshakeType() {

            return TYPE;
        }

        @Override
        byte[] getBytes() throws IOException {
            byte[] message = new byte[messageLength()];
            ByteBuffer m = ByteBuffer.wrap(message);

            ByteBuffers.putInt24(m, messageLength() - 3);
            for (byte[] cert : encodedCertChain) {
                ByteBuffers.putBytes24(m, cert);
            }

            return message;
        }

        @Override
        int messageLength() {

            int msgLen = 3;
            msgLen += encodedCertChain
                    .stream().mapToInt(encodedCert -> encodedCert.length+3).sum();
            return msgLen;
        }
    }


    static class CertificateProducer implements HandshakeProducer {

        @Override
        public HandshakeMessage produce(HandshakeContext handshakeContext) throws SSLException {

            X509Certificate[] certs = handshakeContext.getContextData()
                    .getX509KeyManager()
                    .getCertificateChain("sig", "enc");

            handshakeContext.handshakeSession.setLocalCerts(certs);

            CertificateMessage message = new CertificateMessage(certs);

            return message;
        }

        @Override
        public boolean isNeed(HandshakeContext handshakeContext) {
            //服务端默认需要发送证书
            return !handshakeContext.sslParameters.isClientMode();
        }
    }

    static class CertificateConsumer implements HandshakeConsumer {

        @Override
        public void consume(HandshakeContext handshakeContext, ByteBuffer message) throws IOException {

            CertificateMessage certificateMessage = new CertificateMessage(message);
            List<byte[]> encodedCerts = certificateMessage.encodedCertChain;
            X509Certificate[] x509Certs = new X509Certificate[encodedCerts.size()];

            try {
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                int i = 0;
                for (byte[] encodedCert : encodedCerts) {
                    x509Certs[i++] = (X509Certificate) cf.generateCertificate(
                            new ByteArrayInputStream(encodedCert));
                }
            } catch (CertificateException ce) {
                throw new SSLException(ce);
            }

            checkCerts(x509Certs);
            handshakeContext.handshakeSession.setPeerCerts(x509Certs);
        }


        private void checkCerts(X509Certificate[] x509Certs) {

        }


        @Override
        public SSLHandshakeType handshakeType() {
            return TYPE;
        }

        @Override
        public boolean isNeed(HandshakeContext handshakeContext) {
            //客户端默认需要校验服务端证书
            return handshakeContext.sslParameters.isClientMode();
        }
    }
}
