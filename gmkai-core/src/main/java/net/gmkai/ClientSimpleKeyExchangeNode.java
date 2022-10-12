package net.gmkai;

import net.gmkai.crypto.AsymmetricBlockPadding;
import net.gmkai.crypto.KeyExchangeAlg;
import net.gmkai.crypto.TLSAsymmetricCipher;
import net.gmkai.crypto.TLSCrypto;
import net.gmkai.util.ByteBufferBuilder;
import net.gmkai.util.ByteBuffers;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.Key;
import java.security.SecureRandom;

import static net.gmkai.util.BufferWriteOperations.putBytes16;

public class ClientSimpleKeyExchangeNode extends ClientKeyExchangeNode {


    @Override
    protected void doConsume(HandshakeContext handshakeContext, byte[] message) throws IOException {

        ClientSimpleKeyExchangeMsg clientKeyExchangeMessage =
                new ClientSimpleKeyExchangeMsg(ByteBuffer.wrap(message));

        byte[] encryptedPreMasterSecret =
                clientKeyExchangeMessage.encryptedPreMasterSecret;

        TLSAsymmetricCipher tlsAsymmetricCipher = getTLSAsymmetricCipher(handshakeContext);

        byte[] preMasterSecret =
                tlsAsymmetricCipher.processBlock(encryptedPreMasterSecret
                        , 0, encryptedPreMasterSecret.length);
        handshakeContext.setPreMasterSecret(preMasterSecret);
    }

    @Override
    protected HandshakeMsg doProduce(HandshakeContext handshakeContext) throws IOException {


        byte[] preMasterSecret = getPreMasterSecret(handshakeContext.getCurrentProtocol(), new SecureRandom());

        handshakeContext.setPreMasterSecret(preMasterSecret);

        TLSAsymmetricCipher tlsAsymmetricCipher = getTLSAsymmetricCipher(handshakeContext);

        byte[] encryptedPreSecret = tlsAsymmetricCipher.processBlock(preMasterSecret, 0, preMasterSecret.length);

        return new ClientSimpleKeyExchangeMsg(encryptedPreSecret);
    }

    private byte[] getPreMasterSecret(ProtocolVersion protocolVersion, SecureRandom secureRandom) throws IOException {
        byte[] preSecret = new byte[48];
        ByteBuffer m = ByteBuffer.wrap(preSecret);

        ByteBuffers.putInt16(m, protocolVersion.getId());

        m.put(secureRandom.generateSeed(46));

        return preSecret;
    }

    private TLSAsymmetricCipher getTLSAsymmetricCipher(HandshakeContext handshakeContext) throws SSLException {

        Key key = getTLSAsymmetricCipherKey(handshakeContext);

        TLSCrypto tlsCrypto = handshakeContext.getTLSCrypto();

        KeyExchangeAlg keyExchangeAlg = handshakeContext.getCurrentCipherSuite().keyExchangeAlg;

        boolean forEncrypt = handshakeContext.isClientMode();

        if (keyExchangeAlg == KeyExchangeAlg.K_ECC) {
            return tlsCrypto.getTLSSM2Cipher(forEncrypt, key);
        }
        if (keyExchangeAlg == KeyExchangeAlg.K_RSA) {
            return tlsCrypto.getTLSRSACipher(forEncrypt, AsymmetricBlockPadding.PKCS1Padding, key);
        }
        throw new SSLException("internal error");
    }


    private Key getTLSAsymmetricCipherKey(HandshakeContext handshakeContext) throws SSLException {

        if (handshakeContext.isClientMode()) {
            return handshakeContext.getPeerCertChain()[1].getPublicKey();
        }

        KeyManager keyManager = handshakeContext.getKeyManager();
        TLCPX509Possession possession = handshakeContext.getTLCPX509Possession();

        return possession.getEncPriKey();
    }

    static class ClientSimpleKeyExchangeMsg extends HandshakeMsg {

        private byte[] encryptedPreMasterSecret;

        ClientSimpleKeyExchangeMsg(ByteBuffer byteBuffer) throws IOException {
            super(byteBuffer);
        }

        ClientSimpleKeyExchangeMsg(byte[] encryptedPreMasterSecret) {
            this.encryptedPreMasterSecret = encryptedPreMasterSecret;
        }

        @Override
        HandshakeType getHandshakeType() {
            return HandshakeType.CLIENT_KEY_EXCHANGE;
        }

        @Override
        byte[] getBody() throws IOException {

            return ByteBufferBuilder.
                    bufferCapacity(messageLength()).
                    operate(putBytes16(encryptedPreMasterSecret)).buildByteArray();
        }

        @Override
        int messageLength() {
            return 2 + encryptedPreMasterSecret.length;
        }

        @Override
        void parse(ByteBuffer buffer) throws IOException {
            this.encryptedPreMasterSecret = ByteBuffers.getBytes16(buffer);
        }
    }


}
