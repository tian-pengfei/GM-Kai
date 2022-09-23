package net.gmkai;

import net.gmkai.crypto.SignatureAndHashAlg;
import net.gmkai.crypto.TLSCrypto;
import net.gmkai.crypto.TLSSignatureVerifier;
import net.gmkai.crypto.TLSSigner;
import net.gmkai.util.ByteBufferBuilder;
import net.gmkai.util.ByteBuffers;
import net.gmkai.util.Bytes;
import net.gmkai.util.Certificates;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

import static net.gmkai.util.BufferWriteOperations.putBytes16;

public class ServerSimpleKeyExchangeNode extends ServerKeyExchangeNode {

    @Override
    protected void doConsume(HandshakeContext handshakeContext, byte[] message) throws IOException {

        ServerSimpleKeyExchangeMsg serverSimpleKeyExchangeMsg = new ServerSimpleKeyExchangeMsg(ByteBuffer.wrap(
                message));
        TLSSignatureVerifier tlsSignatureVerifier =
                getTLSSignatureVerifier(handshakeContext);

        tlsSignatureVerifier.addData(toBeSignedData(handshakeContext));

        if (!tlsSignatureVerifier.verifySignature(serverSimpleKeyExchangeMsg.signature)) {
            throw new SSLException("校验失败了");
        }

    }

    @Override
    protected HandshakeMsg doProduce(HandshakeContext handshakeContext) throws IOException {


        TLSSigner tlsSigner = getTLSSigner(handshakeContext);
        tlsSigner.addData(toBeSignedData(handshakeContext));

        return new ServerSimpleKeyExchangeMsg(tlsSigner.getSignature());
    }

    private TLSSigner getTLSSigner(HandshakeContext handshakeContext) {

        KeyManager keyManager = handshakeContext.getKeyManager();
        TLSCrypto tlsCrypto = handshakeContext.getTLSCrypto();
        SignatureAndHashAlg signatureAndHashAlg = handshakeContext.getCurrentCipherSuite().keyExchangeAlg.signatureAndHashAlg;

        if (!(keyManager instanceof InternalTLCPX509KeyManager)) {
            throw new RuntimeException();
        }

        InternalTLCPX509KeyManager internalTLCPX509KeyManager = (InternalTLCPX509KeyManager) keyManager;
        String sigAlias = internalTLCPX509KeyManager.chooseServerSigAlias(signatureAndHashAlg.signAlg.name(), null);

        return tlsCrypto.
                getTLSSigner(internalTLCPX509KeyManager.getPrivateKey(sigAlias), signatureAndHashAlg);
    }

    private TLSSignatureVerifier getTLSSignatureVerifier(HandshakeContext handshakeContext) {

        TLSCrypto tlsCrypto = handshakeContext.getTLSCrypto();

        PublicKey publicKey = handshakeContext.getPeerCertChain()[0].getPublicKey();

        SignatureAndHashAlg signatureAndHashAlg = handshakeContext.getCurrentCipherSuite().keyExchangeAlg.signatureAndHashAlg;

        return tlsCrypto.
                getTLSSignatureVerifier(publicKey, signatureAndHashAlg);
    }

    private byte[] toBeSignedData(HandshakeContext handshakeContext) throws SSLException {

        // encryption cert

        X509Certificate certificate = handshakeContext.isClientMode() ?
                handshakeContext.getPeerCertChain()[1] : handshakeContext.getLocalCertChain()[1];

        byte[] encryptCertBytes = Certificates.x509Certificate2encodedCert(certificate);

        int length = encryptCertBytes.length;

        byte[] lengthBytes = new byte[]{(byte) (length >>> 16 & 0xFF),
                (byte) (length >>> 8 & 0xFF),
                (byte) length};
        return Bytes.
                concat(handshakeContext.getClientRandom(), handshakeContext.getServerRandom(), lengthBytes, encryptCertBytes);

    }

    static class ServerSimpleKeyExchangeMsg extends HandshakeMsg {

        public byte[] signature;

        ServerSimpleKeyExchangeMsg(ByteBuffer message) throws IOException {
            super(message);
        }

        ServerSimpleKeyExchangeMsg(byte[] signature) throws IOException {
            this.signature = signature;
        }

        @Override
        HandshakeType getHandshakeType() {

            return HandshakeType.SERVER_KEY_EXCHANGE;
        }

        @Override
        byte[] getBody() throws IOException {

            return ByteBufferBuilder.
                    bufferCapacity(messageLength()).
                    operate(putBytes16(signature)).buildByteArray();
        }

        @Override
        int messageLength() {
            return 2 + signature.length;
        }

        @Override
        void parse(ByteBuffer buffer) throws IOException {
            signature = ByteBuffers.getBytes16(buffer);
        }
    }
}
