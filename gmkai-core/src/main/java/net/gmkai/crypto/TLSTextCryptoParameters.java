package net.gmkai.crypto;

public class TLSTextCryptoParameters {

    private final BulkCipherAlg bulkCipherAlg;

    private final MacAlg macAlg;

    private final byte[] macKey;

    private final byte[] cryptoKey;

    private final byte[] cryptoKeyIv;


    public TLSTextCryptoParameters(BulkCipherAlg bulkCipherAlg, MacAlg macAlg, byte[] macKey, byte[] cryptoKey, byte[] cryptoKeyIv) {
        this.bulkCipherAlg = bulkCipherAlg;
        this.macAlg = macAlg;
        this.macKey = macKey;
        this.cryptoKey = cryptoKey;
        this.cryptoKeyIv = cryptoKeyIv;
    }

    public BulkCipherAlg getBulkCipherAlg() {
        return bulkCipherAlg;
    }

    public MacAlg getMacAlg() {
        return macAlg;
    }

    public byte[] getMacKey() {
        return macKey;
    }

    public byte[] getCryptoKey() {
        return cryptoKey;
    }

    public byte[] getCryptoKeyIv() {
        return cryptoKeyIv;
    }


}
