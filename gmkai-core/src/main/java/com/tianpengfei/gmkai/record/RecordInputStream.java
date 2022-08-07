package com.tianpengfei.gmkai.record;

import com.tianpengfei.gmkai.ProtocolVersion;
import com.tianpengfei.gmkai.alert.Alert;
import com.tianpengfei.gmkai.alert.AlertException;
import com.tianpengfei.gmkai.handshake.SSLHandshakeType;

import javax.net.ssl.SSLException;
import java.io.ByteArrayInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;

public class RecordInputStream {

    InputStream inputStream;

    SSLReadCipher sslReadCipher;

    RecordInputStream(InputStream inputStream) {
        this.inputStream = inputStream;
    }

    public void updateCipher(RecordKeySet keySet) {
        sslReadCipher = new SSLReadCipher(keySet.peerMacKey, keySet.peerWriteKey, keySet.peerWriteIv);
    }


    public Plaintext readPlaintext() throws IOException {

        ContentType type = ContentType.valueOf(inputStream.read());
        if (type == null) {
            System.out.println("type:" + type);
            throw new SSLException("没见过这种类型的");
        }

        ProtocolVersion version = ProtocolVersion.valueOf(
                ((inputStream.read() & 0xFF) << 8) | (inputStream.read() & 0xFF));

        int length = ((inputStream.read() & 0xFF) << 8)
                | (inputStream.read() & 0xFF);
        byte[] content = safeRead(inputStream, length);

//        inputStream.read(content);


        if (type == ContentType.ALERT) {
            Alert alert = Alert.read(new ByteArrayInputStream(content));
            throw new AlertException(alert, true);

        }

        Plaintext plaintext;

        if (sslReadCipher == null) {
            plaintext = new Plaintext(type, version, content);
        } else {
            plaintext = sslReadCipher.decrypt(new Plaintext(type, version, content));
        }

        System.out.println("接收到消息类型为：" + (type == ContentType.HANDSHAKE ? type + ":" +
                SSLHandshakeType.valueOf(plaintext.fragment[0]) : type) + (sslReadCipher == null ? "" : "(加密)"));

        return plaintext;
    }

    public void close() throws IOException {
        inputStream.close();
    }

    public static byte[] safeRead(InputStream input, int len) throws IOException {
        byte[] buf = new byte[len];
        int count = 0;
        while (count < len) {
            int l = input.read(buf, count, len - count);
            if (l == -1) {
                throw new EOFException("unexpected end of stream");
            }
            count += l;
        }
        return buf;
    }

}
