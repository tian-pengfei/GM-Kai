package net.gmkai.crypto.impl.bc;

import net.gmkai.crypto.MacAlg;
import net.gmkai.crypto.TLSCrypto;
import net.gmkai.crypto.TLSHMac;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.macs.HMac;

public class BcTLSCrypto implements TLSCrypto {


    @Override
    public TLSHMac createHMAC(MacAlg macAlg){

        Digest digest;

        switch (macAlg){
            case SM3:
                digest = new SM3Digest();
                break;
            case SHA256:
                digest = new SHA256Digest();
                break;
            default:
                throw new IllegalStateException("Unexpected value: " + macAlg);
        }

        HMac hMac = new HMac(digest);

        return new BcTLSHMac(hMac);
    }



}
