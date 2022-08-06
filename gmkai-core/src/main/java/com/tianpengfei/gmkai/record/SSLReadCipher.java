package com.tianpengfei.gmkai.record;

import com.tianpengfei.gmkai.util.ByteBuffers;
import com.tianpengfei.gmkai.util.bc.SM3Util;
import com.tianpengfei.gmkai.util.bc.SM4Util;

import javax.net.ssl.SSLException;
import java.nio.ByteBuffer;
import java.util.Arrays;

public class SSLReadCipher {

    byte[] peerMacKey;

    byte[] peerWriteKey;

    byte[] peerWriteIv;

    SequenceNumber sequenceNumber;

    SSLReadCipher(byte[] peerMacKey, byte[] peerWriteKey, byte[] peerWriteIv) {
        this.peerMacKey = peerMacKey;
        this.peerWriteKey = peerWriteKey;
        this.peerWriteIv = peerWriteIv;
        this.sequenceNumber = new SequenceNumber();
    }

    Plaintext decrypt(Plaintext encrypted) throws SSLException {
        try {


            byte[] src = SM4Util.decrypt_CBC_SSL3Padding(peerWriteKey, peerWriteIv, encrypted.getFragment());

            ByteBuffer b = ByteBuffer.wrap(src);

            byte[] iv = new byte[16];

            byte[] content = new byte[src.length - 16 - 32];

            byte[] serverMac = new byte[32];

            b.get(iv);
            b.get(content);
            b.get(serverMac);

            ByteBuffer buffer = ByteBuffer.allocate(8 + 1 + 2 + 2 + content.length);

            // seq_num
            ByteBuffers.putLong64(buffer, sequenceNumber.nextValue());

            //content_type
            buffer.put(encrypted.contentType.id);

            //version
            ByteBuffers.putInt16(buffer, encrypted.version.getId());
            //fragment_length+fragment
            ByteBuffers.putBytes16(buffer, content);

            byte[] mac = SM3Util.hmac(peerMacKey, buffer.array());

            if (!Arrays.equals(mac, serverMac)) {
                throw new SSLException("完整性校验失败");
            }

            return new Plaintext(encrypted.contentType, encrypted.version, content);

        } catch (Exception e) {
            throw new SSLException("解密失败:" + e.getMessage(), e);
        }
    }
}
