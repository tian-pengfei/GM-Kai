package net.gmkai.crypto;


import java.security.Key;

public abstract class TLSRSACipher implements TLSAsymmetricBlockCipher {

    final boolean forEncryption;

    protected final AsymmetricBlockPadding blockPadding;

    protected final Key key;

    public TLSRSACipher(boolean forEncryption, AsymmetricBlockPadding blockPadding, Key key) {
        this.blockPadding = blockPadding;
        this.key = key;
        this.forEncryption = forEncryption;
    }

    public AsymmetricBlockPadding getBlockPadding() {
        return blockPadding;
    }

}
