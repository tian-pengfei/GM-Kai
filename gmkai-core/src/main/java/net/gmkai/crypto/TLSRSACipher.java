package net.gmkai.crypto;


import java.security.interfaces.RSAKey;

public abstract class TLSRSACipher implements TLSAsymmetricBlockCipher {

    final boolean forEncryption;

    protected final AsymmetricBlockPadding blockPadding;

    protected final RSAKey rsaKey;

    public TLSRSACipher(boolean forEncryption, AsymmetricBlockPadding blockPadding, RSAKey rsaKey) {
        this.blockPadding = blockPadding;
        this.rsaKey = rsaKey;
        this.forEncryption = forEncryption;
    }

    public AsymmetricBlockPadding getBlockPadding() {
        return blockPadding;
    }

}
