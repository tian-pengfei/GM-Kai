package net.gmkai;

import net.gmkai.crypto.TLSCrypto;
import net.gmkai.crypto.TLSCryptoParameters;
import net.gmkai.crypto.TLSPrf;
import net.gmkai.crypto.TLSTextCipher;
import net.gmkai.crypto.impl.TLSNullCipher;
import net.gmkai.event.*;
import net.gmkai.util.Bytes;

import javax.net.ssl.SSLException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;

import static net.gmkai.util.ByteBuffers.getBytes;

class RecordTransport implements
        ApplicationMsgTransport,
        AlertSender,
        HandshakeMsgTransport {

    private final InputStream inputStream;

    private final OutputStream outputStream;

    private TLSTextCipher tlsReadCipher = TLSNullCipher.NULL_CIPHER;

    private TLSTextCipher tlsWriteCipher = TLSNullCipher.NULL_CIPHER;

    boolean readable = true;

    boolean writeable = true;

    private final TLSCrypto tlsCrypto;

    private TLSCryptoParameters tlsCryptoParameters;

    private ProtocolVersion protocolVersion = ProtocolVersion.TLCP11;

    public RecordTransport(TLSEventBus eventBus, TLSCrypto tlsCrypto, InputStream inputStream, OutputStream outputStream) {

        this.tlsCrypto = tlsCrypto;

        this.inputStream = inputStream;

        this.outputStream = outputStream;

        RecordListener recordListener = new RecordListener();

        eventBus.register(recordListener);
    }

    @Override
    public void sendAlert(final byte[] alertMsg) throws IOException {

        writeRecord(ContentType.ALERT, protocolVersion, alertMsg);
    }

    @Override
    public TLSText readApplicationMsg() throws IOException {

        return readRecord(ContentType.APPLICATION_DATA);
    }

    @Override
    public void writeApplicationMsg(final byte[] applicationMsg) throws IOException {

        writeRecord(ContentType.APPLICATION_DATA, protocolVersion, applicationMsg);

    }

    @Override
    public HandshakeMsg readHandshakeMsg() throws IOException {

        TLSText tlsText = readRecord(ContentType.HANDSHAKE);

        return HandshakeMsg.getInstance(tlsText.fragment);
    }

    @Override
    public void writeHandshakeMsg(HandshakeMsg handshakeMsg) throws IOException {

        writeRecord(ContentType.HANDSHAKE, protocolVersion, handshakeMsg.getMsg());
    }

    private void handleUnexpectedMsg(TLSText tlsText) throws SSLException {
        //触发事件
    }

    private void updateCryptoParameters(TLSCryptoParameters tlsCryptoParameters) {
        this.tlsCryptoParameters = tlsCryptoParameters;
    }

    private void updateWriteCipher() throws IOException {
        tlsWriteCipher = tlsCrypto.
                createTLSTextCipher(true, tlsCryptoParameters.getWriteTLSTextCryptoParameters());
    }

    private void updateReadCipher() throws IOException {
        tlsReadCipher = tlsCrypto.
                createTLSTextCipher(false, tlsCryptoParameters.getReadTLSTextCryptoParameters());
    }

    private void writeRecord(final ContentType contentType, final ProtocolVersion protocolVersion, final byte[] fragment) throws IOException {
        if (!writeable) throw new SSLException("");

        TLSText tlsText = tlsWriteCipher.processTLSText(
                new TLSText(contentType, protocolVersion, fragment));

        byte[] data = tlsText.toBytes();
        outputStream.write(data);
    }

    private TLSText readRecord(final ContentType contentType) throws IOException {

        TLSText tlsText = null;

        while (readable) {

            tlsText = tlsReadCipher.processTLSText(TLSText.readTLSText(inputStream));

            if (contentType == tlsText.contentType) break;

            handleUnexpectedMsg(tlsText);
        }

        return tlsText;
    }

    private TLSCryptoParameters SecurityParameters2TLSCryptoParameters(SecurityParameters securityParameters) throws IOException {

        TLSPrf prf = tlsCrypto.createTLSPrf(securityParameters.getMacAlg());

        byte[] keyBlock = prf.prf(
                securityParameters.getMasterSecret(),
                "key expansion",
                Bytes.concat(securityParameters.getServerRandom(), securityParameters.getClientRandom()),
                128);


        ByteBuffer keyBuffer = ByteBuffer.wrap(keyBlock);

        if (securityParameters.getConnectionEnd() == ConnectionEnd.CLIENT) {

            return TLSCryptoParameters.TLSCryptoParametersBuilder.aTLSCryptoParameters().
                    withMacAlg(securityParameters.getMacAlg()).
                    withBulkCipherAlg(securityParameters.getBulkCipherAlg()).

                    withSelfMacKey(getBytes(keyBuffer, 32)).
                    withPeerMackey(getBytes(keyBuffer, 32)).

                    withSelfCryptoKey(getBytes(keyBuffer, 16)).
                    withPeerCryptoKey(getBytes(keyBuffer, 16)).

                    withSelfCryptoKeyIv(getBytes(keyBuffer, 16)).
                    withPeerCryptoKeyIv(getBytes(keyBuffer, 16)).build();
        }
        return TLSCryptoParameters.TLSCryptoParametersBuilder.aTLSCryptoParameters().
                withMacAlg(securityParameters.getMacAlg()).
                withBulkCipherAlg(securityParameters.getBulkCipherAlg()).

                withPeerMackey(getBytes(keyBuffer, 32)).
                withSelfMacKey(getBytes(keyBuffer, 32)).

                withPeerCryptoKey(getBytes(keyBuffer, 16)).
                withSelfCryptoKey(getBytes(keyBuffer, 16)).

                withPeerCryptoKeyIv(getBytes(keyBuffer, 16)).
                withSelfCryptoKeyIv(getBytes(keyBuffer, 16)).build();
    }

    private class RecordListener implements ChangeWriteCipherListener,
            ChangeReadCipherListener,
            GenerateSecurityParametersFinishedListener,
            DefiniteProtocolFinishedListener {


        @Override
        public void changeReadCipher(ChangeReadCipherEvent event) {
            try {
                updateReadCipher();
            } catch (IOException e) {
                throw new RuntimeException(e.getMessage(), e);
            }
        }

        @Override
        public void changeWriteCipher(ChangeWriteCipherEvent event) {
            try {
                updateWriteCipher();
            } catch (IOException e) {
                throw new RuntimeException(e.getMessage(), e);
            }
        }

        @Override
        public void DefiniteProtocol(DefiniteProtocolFinishedEvent event) {
            protocolVersion = event.getProtocol();
        }

        @Override
        public void setSecurityParameters(GenerateSecurityParametersFinishedEvent event) {
            try {
                updateCryptoParameters(SecurityParameters2TLSCryptoParameters(event.getSecurityParameters()));
            } catch (IOException e) {
                throw new RuntimeException(e.getMessage(), e);
            }
        }
    }
}
