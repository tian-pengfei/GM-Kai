package net.gmkai.crypto.impl.bc;

import net.gmkai.crypto.*;
import net.gmkai.crypto.padding.Padding;
import net.gmkai.crypto.padding.TLSPadding;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.engines.SM4Engine;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.modes.CBCBlockCipher;

import java.io.IOException;

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

    @Override
    public TLSBlockCipher createTLSBlockCipher(TLSCryptoParameters cryptoParameters) throws IOException {
        if (cryptoParameters.getBulkCipherAlg().cipherType != TLSCipherType.BLOCK_CIPHER) {
            throw new RuntimeException();
        }
        BcTLSBlockCipherImpl encrypt = new BcTLSBlockCipherImpl(createBlockCipher(cryptoParameters.getBulkCipherAlg()), true);
        BcTLSBlockCipherImpl decrypt = new BcTLSBlockCipherImpl(createBlockCipher(cryptoParameters.getBulkCipherAlg()), false);
        Padding padding = new TLSPadding();

        return new TLSBlockCipher(cryptoParameters,
                encrypt, decrypt, createHMAC(cryptoParameters.getMacAlg()), createHMAC(cryptoParameters.getMacAlg()),
                cryptoParameters.getBulkCipherAlg().cipherKeySize, padding);
    }

    BlockCipher createBlockCipher(BulkCipherAlg bulkCipherAlg) {
        switch (bulkCipherAlg) {
            case SM4_CBC:
                return new CBCBlockCipher(new SM4Engine());
            default:
                throw new IllegalStateException("Unexpected value: " + bulkCipherAlg);
        }

    }


}
