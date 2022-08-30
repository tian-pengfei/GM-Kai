package net.gmkai.crypto.impl.bc;

import net.gmkai.crypto.*;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.macs.HMac;

public class BcTLSCrypto implements TLSCrypto {


    @Override
    public TLSHMac createHMAC(MacAlg macAlg) {

        switch (macAlg) {
            case M_SM3:
                return new BcTLSHMac(new HMac(new SM3Digest()));
            case M_SHA256:
                return new BcTLSHMac(new HMac(new SHA256Digest()));
            default:
                throw new IllegalStateException("Unexpected value: " + macAlg);
        }

    }

    @Override
    public TLSHash createHash(HashAlg hashAlg) {
        switch (hashAlg) {
            case H_SM3:
                return new BcTLSHash(new SM3Digest());
            case H_SHA256:
                return new BcTLSHash(new SHA256Digest());
            default:
                throw new IllegalStateException("Unexpected value: " + hashAlg);
        }
    }


}
