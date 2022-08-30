package net.gmkai.crypto.impl.bc;

import net.gmkai.crypto.TLSHash;
import org.bouncycastle.crypto.Digest;

class BcTLSHash implements TLSHash {

    private final Digest digest;

    BcTLSHash(Digest digest) {
        this.digest = digest;
    }

    @Override
    public void update(byte[] input, int inOff, int length) {
        digest.update(input, inOff, length);
    }

    @Override
    public byte[] calculateHash() {
        byte[] hash = new byte[digest.getDigestSize()];
        digest.doFinal(hash, 0);
        return hash;
    }

    @Override
    public void calculateHash(byte[] output, int outOff) {
        digest.doFinal(output, outOff);
    }

    @Override
    public void reset() {
        digest.reset();
    }
}
