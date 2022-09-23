package net.gmkai;

import net.gmkai.util.ByteBuffers;
import net.gmkai.util.Certificates;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

public class CertificateNode extends HandshakeNode {

    final private HandshakeOptional optional;

    final private HandshakeConsumable consumable;

    CertificateNode(HandshakeOptional optional, HandshakeConsumable consumable) {
        this.consumable = consumable;
        this.optional = optional;
    }

    @Override
    protected void doConsume(HandshakeContext handshakeContext, byte[] message) throws IOException {

        CertificateMsg certificateMsg = new CertificateMsg(ByteBuffer.wrap(message));
        X509Certificate[] chain = certificateMsg.getX509Certificates();
        checkTrust(handshakeContext, chain);
        handshakeContext.setPeerCertChain(chain);
    }

    @Override
    protected HandshakeMsg doProduce(HandshakeContext handshakeContext) throws SSLException {

        X509Certificate[] certs = getCertChain(handshakeContext);

        handshakeContext.setLocalCertChain(certs);

        return new CertificateMsg(certs);
    }

    @Override
    public HandshakeType getHandshakeType() {

        return HandshakeType.CERTIFICATE;
    }

    @Override
    public boolean consumable(HandshakeContext handshakeContext) {
        return optional.optional(handshakeContext);
    }

    @Override
    public boolean optional(HandshakeContext handshakeContext) {
        return consumable.consumable(handshakeContext);
    }


    private void checkTrust(HandshakeContext handshakeContext, X509Certificate[] chain) throws SSLException {

        InternalX509TrustManager x509TrustManager = handshakeContext.getX509TrustManager();

        TLSCipherSuite tlsCipherSuite = handshakeContext.getCurrentCipherSuite();

        try {
            if (handshakeContext.isClientMode()) {
                x509TrustManager.checkServerTrusted(chain, tlsCipherSuite.keyExchangeAlg.name);
            } else {
                x509TrustManager.checkClientTrusted(chain, tlsCipherSuite.keyExchangeAlg.name);
            }
        } catch (CertificateException e) {
            throw new SSLException(e.getMessage(), e);
        }
    }

    private X509Certificate[] getCertChain(HandshakeContext handshakeContext) throws SSLException {

        KeyManager x509KeyManager = handshakeContext.getKeyManager();

        if (x509KeyManager instanceof InternalTLCPX509KeyManager) {

            InternalTLCPX509KeyManager tlcpx509KeyManager = (InternalTLCPX509KeyManager) x509KeyManager;
            TLSCipherSuite tlsCipherSuite = handshakeContext.getCurrentCipherSuite();

            String sig = tlcpx509KeyManager.chooseServerSigAlias(tlsCipherSuite.name, null);
            String enc = tlcpx509KeyManager.chooseServerEncAlias(tlsCipherSuite.name, null);

            return tlcpx509KeyManager.getCertificateChain(sig, enc);
        }

        throw new SSLException("fail to get chain");
    }


    @Override
    public void doAfterConsume(HandshakeContext handshakeContext) {
    }

    @Override
    public void doAfterProduce(HandshakeContext handshakeContext) {
    }


    static class CertificateMsg extends HandshakeMsg {

        /**
         * ASN.1Cert
         */
        List<byte[]> certificates;

        CertificateMsg(List<byte[]> certificates) {
            this.certificates = certificates;
        }

        CertificateMsg(X509Certificate[] x509Certificates) throws SSLException {
            int size = x509Certificates.length;
            certificates = new ArrayList<>(size);

            for (int i = 0; i < size; i++) {
                certificates.add(i, Certificates.x509Certificate2encodedCert(x509Certificates[i]));
            }

        }

        CertificateMsg(ByteBuffer buffer) throws IOException {
            super(buffer);
        }

        @Override
        HandshakeType getHandshakeType() {
            return HandshakeType.CERTIFICATE;
        }

        @Override
        byte[] getBody() throws IOException {

            byte[] message = new byte[messageLength()];
            ByteBuffer m = ByteBuffer.wrap(message);
            ByteBuffers.putInt24(m, messageLength() - 3);

            for (byte[] cert : certificates) {
                ByteBuffers.putBytes24(m, cert);
            }
            return message;
        }

        @Override
        int messageLength() {
            int msgLen = 3;
            msgLen += certificates.stream().mapToInt(encodedCert -> encodedCert.length + 3).sum();
            return msgLen;
        }

        @Override
        void parse(ByteBuffer buffer) throws IOException {
            certificates = new ArrayList<>();

            int len = ByteBuffers.getInt24(buffer);
            while (len > 0) {
                byte[] encodedCert = ByteBuffers.getBytes24(buffer);
                len -= 3 + encodedCert.length;
                certificates.add(encodedCert);
            }
        }

        X509Certificate[] getX509Certificates() throws SSLException {
            X509Certificate[] x509Certificates = new X509Certificate[certificates.size()];
            for (int i = 0; i < x509Certificates.length; i++) {
                x509Certificates[i] = Certificates.encodedCert2x509Certificate(certificates.get(i));
            }
            return x509Certificates;
        }
    }
}
