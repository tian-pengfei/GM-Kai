package net.gmkai;

import net.gmkai.crypto.TLSCrypto;
import net.gmkai.crypto.TLSCryptoParameters;
import net.gmkai.crypto.TLSTextCipher;
import net.gmkai.crypto.impl.TLSNullCipher;

import javax.net.ssl.SSLException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

class RecordTransport implements ApplicationMsgTransport, AlertSender, HandshakeMsgTransport {

    private final InputStream inputStream;

    private final OutputStream outputStream;

    private TLSTextCipher tlsReadCipher = TLSNullCipher.NULL_CIPHER;

    private TLSTextCipher tlsWriteCipher = TLSNullCipher.NULL_CIPHER;

    boolean readable = true;

    boolean writeable = true;

    private final TLSCrypto tlsCrypto;

    TLSCryptoParameters tlsCryptoParameters;

    public RecordTransport(TLSCrypto tlsCrypto, InputStream inputStream, OutputStream outputStream) {

        this.tlsCrypto = tlsCrypto;

        this.inputStream = inputStream;

        this.outputStream = outputStream;
    }

    @Override
    public void sendAlert(final byte[] alertMsg) throws IOException {

        writeRecord(ContentType.ALERT, ProtocolVersion.TLCP11, alertMsg);
    }

    @Override
    public TLSText readApplicationMsg() throws IOException {

        return readRecord(ContentType.APPLICATION_DATA);
    }

    @Override
    public void writeApplicationMsg(final byte[] applicationMsg) throws IOException {

        writeRecord(ContentType.APPLICATION_DATA, ProtocolVersion.TLCP11, applicationMsg);

    }

    @Override
    public TLSText readHandshakeMsg() throws IOException {

        return readRecord(ContentType.HANDSHAKE);
    }

    @Override
    public void writeHandshakeMsg(final byte[] handshakeMsg) throws IOException {

        writeRecord(ContentType.HANDSHAKE, ProtocolVersion.TLCP11, handshakeMsg);
    }

    private void handleUnexpectedMsg(TLSText tlsText) throws SSLException {
        //触发事件
    }

    public void updateCryptoParameters(TLSCryptoParameters tlsCryptoParameters) {
        this.tlsCryptoParameters = tlsCryptoParameters;
    }

    public void updateWriteCipher() throws IOException {
        tlsWriteCipher = tlsCrypto.
                createTLSTextCipher(true, tlsCryptoParameters.getWriteTLSTextCryptoParameters());
    }

    public void updateReadCipher() throws IOException {
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

}
