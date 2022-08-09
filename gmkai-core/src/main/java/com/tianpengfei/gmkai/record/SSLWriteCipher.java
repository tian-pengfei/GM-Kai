package com.tianpengfei.gmkai.record;

import com.tianpengfei.gmkai.util.ByteBuffers;
import com.tianpengfei.gmkai.util.Bytes;
import com.tianpengfei.gmkai.util.bc.SM4Util;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;

import javax.net.ssl.SSLException;
import java.io.IOException;
import java.nio.ByteBuffer;

public class SSLWriteCipher {

    byte[] macKey;

    byte[] writeKey;

    byte[] writeIv;
    SequenceNumber sequenceNumber = new SequenceNumber();

    public SSLWriteCipher(byte[] macKey, byte[] writeKey, byte[] writeIv) {
        this.macKey = macKey;
        this.writeKey = writeKey;
        this.writeIv = writeIv;
    }


    Plaintext encrypt(Plaintext plaintext) throws IOException {

        //计算mac
        ByteBuffer buffer = ByteBuffer.allocate(8 + 1 + 2 + 2 + plaintext.fragment.length);

        // seq_num
        ByteBuffers.putLong64(buffer, sequenceNumber.nextValue());

        //content_type
        buffer.put(plaintext.contentType.id);

        //version
        ByteBuffers.putInt16(buffer, plaintext.version.getId());
        //fragment_length+fragment
        ByteBuffers.putBytes16(buffer, plaintext.fragment);

        byte[] mac = hmacHash(buffer.array(), macKey);
//        System.out.println("mac:" + Hex.toHexString(mac));

        byte[] contentWithMac = Bytes.combine(writeIv, plaintext.fragment, mac);

        //加密
        byte[] encryptedContent;
        try {
            encryptedContent = SM4Util.encrypt_CBC_SSL3Padding(writeKey, writeIv, contentWithMac);

        } catch (Exception e) {
            throw new SSLException("加密失败:" + e.getMessage(), e);
        }
        return new Plaintext(plaintext.contentType, plaintext.version, encryptedContent);
    }


    private static byte[] hmacHash(byte[] data, byte[] secret) {
        KeyParameter keyParameter = new KeyParameter(secret);
        SM3Digest digest = new SM3Digest();
        HMac mac = new HMac(digest);
        mac.init(keyParameter);
        mac.update(data, 0, data.length);
        byte[] out = new byte[mac.getMacSize()];
        mac.doFinal(out, 0);
        return out;
    }


}
