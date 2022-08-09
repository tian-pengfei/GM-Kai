package com.tianpengfei.gmkai.record;

import com.tianpengfei.gmkai.handshake.SSLHandshakeType;
import com.tianpengfei.gmkai.util.ByteBuffers;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;

public class RecordOutputStream {


    OutputStream outputStream;

    SSLWriteCipher writeCipher;

    RecordOutputStream(OutputStream outputStream) {
        this.outputStream = outputStream;
    }

    public void updateCipher(RecordKeySet keySet) {
        writeCipher = new SSLWriteCipher(keySet.macKey, keySet.writeKey, keySet.writeIv);
    }

    void writeRecord(Plaintext plaintext) throws IOException {
        Plaintext cipherText = null;

        if (writeCipher == null) {
            cipherText = plaintext;
        } else {
            cipherText = writeCipher.encrypt(plaintext);
        }

        ByteBuffer buffer = ByteBuffer.allocate(1 + 2 + 2 + cipherText.fragment.length);

        buffer.put(cipherText.contentType.id);
        ByteBuffers.putInt16(buffer, cipherText.version.getId());
        ByteBuffers.putBytes16(buffer, cipherText.fragment);

        outputStream.write(buffer.array());
        outputStream.flush();
        ContentType type = plaintext.contentType;
        System.out.println("发送到消息类型为：" + (type == ContentType.HANDSHAKE ? type + ":" +
                SSLHandshakeType.valueOf(plaintext.fragment[0]) : type) + (writeCipher == null ? "" : "(加密)"));

    }

    public void close() throws IOException {
        outputStream.close();
    }

}
