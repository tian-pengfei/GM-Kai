package com.tianpengfei.gmkai.handshake;

import com.google.common.collect.Lists;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SM3Digest;

import java.util.List;

public class HandshakeHash {

    Digest digest;

    List<byte[]> data = Lists.newArrayList();

    HandshakeHash() {
        digest = new SM3Digest();
    }

    HandshakeHash(Digest digest) {
        this.digest = digest;
    }

    public void update(byte[] message) {
        data.add(message);
    }

    public byte[] finish() {
        byte[] hash = new byte[digest.getDigestSize()];
        data.forEach(d -> {
            digest.update(d, 0, d.length);
        });

        digest.doFinal(hash, 0);
        return hash;
    }

    public void reset() {
        data = Lists.newArrayList();
    }
}
