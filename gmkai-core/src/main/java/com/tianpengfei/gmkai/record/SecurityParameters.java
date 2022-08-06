package com.tianpengfei.gmkai.record;


import com.tianpengfei.gmkai.cipher.Crypto;
import com.tianpengfei.gmkai.util.Bytes;
import org.bouncycastle.crypto.engines.SM4Engine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.tls.ConnectionEnd;
import org.bouncycastle.util.encoders.Hex;

import javax.net.ssl.SSLException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

public class SecurityParameters {


    int entity;

    //.....

    byte[] clientRandom;

    byte[] serverRandom;

    byte[] masterSecret;

    public SecurityParameters(int entity, byte[] clientRandom, byte[] serverRandom, byte[] masterSecret) {
        this.entity = entity;
        this.clientRandom = clientRandom;
        this.serverRandom = serverRandom;
        this.masterSecret = masterSecret;


    }

    RecordKeySet getRecordKetSet() throws IOException {

        RecordKeySet keySet = new RecordKeySet();
        try {
            byte[] keyBlock = Crypto.prf(masterSecret, "key expansion".getBytes(StandardCharsets.UTF_8), Bytes.combine(serverRandom, clientRandom)
                    , 128);


            ByteBuffer keyBuffer = ByteBuffer.wrap(keyBlock);
            if (entity == ConnectionEnd.client) {
                keyBuffer.get(keySet.macKey);
                keyBuffer.get(keySet.peerMacKey);
                keyBuffer.get(keySet.writeKey);
                keyBuffer.get(keySet.peerWriteKey);
                keyBuffer.get(keySet.writeIv);
                keyBuffer.get(keySet.peerWriteIv);
//                System.out.println(Hex.toHexString(keySet.macKey));
//                System.out.println(Hex.toHexString(keySet.peerMacKey));
//                System.out.println(Hex.toHexString(keySet.writeKey));
//                System.out.println(Hex.toHexString(keySet.peerWriteKey));
//                System.out.println(Hex.toHexString(keySet.writeIv));
//                System.out.println(Hex.toHexString(keySet.peerWriteIv));

            } else {
                keyBuffer.get(keySet.peerMacKey);
                keyBuffer.get(keySet.macKey);
                keyBuffer.get(keySet.peerWriteKey);
                keyBuffer.get(keySet.writeKey);
                keyBuffer.get(keySet.peerWriteIv);
                keyBuffer.get(keySet.writeIv);
            }

        } catch (Exception e) {
            throw new SSLException("工作密钥生成失败");
        }
//        me();
        return keySet;
    }

    void me() throws IOException {
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        os.write(serverRandom);
        os.write(clientRandom);
        byte[] seed = os.toByteArray();
        byte[] keyBlock = null;
        try {
            keyBlock = Crypto.prf(masterSecret, "key expansion".getBytes(), seed, 128);
        } catch (Exception e) {
            throw new SSLException("caculate key block failed", e);
        }

        // client_write_MAC_secret[SecurityParameters.hash_size]
        // server_write_MAC_secret[SecurityParameters.hash_size]
        // client_write_key[SecurityParameters.key_material_length]
        // server_write_key[SecurityParameters.key_material_length]
        // clientWriteIV
        // serverWriteIV

        // client mac key
        byte[] clientMacKey = new byte[32];
        System.arraycopy(keyBlock, 0, clientMacKey, 0, 32);
        System.out.println(Hex.toHexString(clientMacKey));

        // server mac key
        byte[] serverMacKey = new byte[32];
        System.arraycopy(keyBlock, 32, serverMacKey, 0, 32);
        System.out.println(Hex.toHexString(serverMacKey));

        // client write key
        byte[] clientWriteKey = new byte[16];
        System.arraycopy(keyBlock, 64, clientWriteKey, 0, 16);
        System.out.println(Hex.toHexString(clientWriteKey));
        ;

        // server write key
        byte[] serverWriteKey = new byte[16];
        System.arraycopy(keyBlock, 80, serverWriteKey, 0, 16);
        System.out.println(Hex.toHexString(serverWriteKey));
        ;

        // client write iv
        byte[] clientWriteIV = new byte[16];
        System.arraycopy(keyBlock, 96, clientWriteIV, 0, 16);
        System.out.println(Hex.toHexString(clientWriteIV));
        ;

        // server write iv
        byte[] serverWriteIV = new byte[16];
        System.arraycopy(keyBlock, 112, serverWriteIV, 0, 16);
        System.out.println(Hex.toHexString(serverWriteIV));
        ;
    }

}
