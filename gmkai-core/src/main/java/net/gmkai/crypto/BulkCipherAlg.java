package net.gmkai.crypto;

public enum BulkCipherAlg {

    SM4_CBC("SM4_CBC", TLSCipherType.BLOCK_CIPHER, 16, 16),

    SM4_GCM("SM4_GCM", TLSCipherType.AEAD_CIPHER, 16, 0);


    public final String name;

    public final TLSCipherType cipherType;

    public final int cipherKeySize;

    public final int ivLength;

    BulkCipherAlg(String name, TLSCipherType cipherType, int cipherKeySize, int ivLength) {
        this.name = name;
        this.cipherType = cipherType;
        this.cipherKeySize = cipherKeySize;
        this.ivLength = ivLength;
    }

}