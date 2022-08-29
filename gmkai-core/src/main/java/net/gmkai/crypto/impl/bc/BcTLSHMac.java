package net.gmkai.crypto.impl.bc;

import net.gmkai.crypto.TLSHMac;
import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;

class BcTLSHMac implements TLSHMac {

    private final HMac hmac;

    BcTLSHMac(HMac hmac){
        this.hmac = hmac;
    }

    @Override
    public void setKey(byte[] key, int keyOff, int keyLen) {
        hmac.init(new KeyParameter(key, keyOff, keyLen));
    }

    @Override
    public void update(byte[] input, int inOff, int length) {
        hmac.update(input, inOff, length);
    }

    @Override
    public byte[] calculateMAC() {
        byte[] rv = new byte[hmac.getMacSize()];

        hmac.doFinal(rv, 0);

        return rv;
    }

    @Override
    public void calculateMAC(byte[] output, int outOff) {
        hmac.doFinal(output, outOff);
    }

    @Override
    public int getMacLength() {
        return hmac.getMacSize();
    }

    @Override
    public void reset() {
        hmac.reset();
    }

    @Override
    public int getInternalBlockSize() {
        return ((ExtendedDigest)hmac.getUnderlyingDigest()).getByteLength();
    }
}
