package com.tianpengfei.gmkai.record;

import com.tianpengfei.gmkai.ProtocolVersion;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;

/**
 * 记录层协议
 */
public class Record {


    private final RecordInputStream inputStream;

    private final RecordOutputStream outputStream;

    private RecordKeySet keySet;

    public Record(InputStream inputStream, OutputStream outputStream) {

        this.inputStream = new RecordInputStream(inputStream);

        this.outputStream = new RecordOutputStream(outputStream);


    }

    public Plaintext read() throws IOException {
        return inputStream.readPlaintext();
    }

    public void write(
            ContentType contentType, ProtocolVersion version, ByteBuffer src) throws IOException {
        outputStream.writeRecord(new Plaintext(contentType, version, src.array()));
    }

    public void writeAlert(ByteBuffer src) throws IOException {
        write(ContentType.ALERT, ProtocolVersion.GMSSL11, src);
    }

    public void writeHandshake(ByteBuffer src) throws IOException {
        write(ContentType.HANDSHAKE, ProtocolVersion.GMSSL11, src);
    }


    public void writeChangeCipherSpec(ByteBuffer src) throws IOException {
        write(ContentType.CHANGE_CIPHER_SPEC, ProtocolVersion.GMSSL11, src);

    }

    public void writeApplication(ByteBuffer src) throws IOException {

        write(ContentType.APPLICATION_DATA, ProtocolVersion.GMSSL11, src);

    }


    public void updateSecurityParameters(SecurityParameters securityParameters) throws IOException {

        this.keySet = securityParameters.getRecordKetSet();
    }

    public void updateReadKey() {

        inputStream.updateCipher(keySet);

    }

    public void updateWriteKey() {
        outputStream.updateCipher(keySet);

    }


    public void closeRead() throws IOException {
        inputStream.close();
    }

    public void closeWrite() throws IOException {
        outputStream.close();
    }
}
