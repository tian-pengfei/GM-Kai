package net.gmkai.crypto;

public class TLSCryptoParameters {


    private final BulkCipherAlg bulkCipherAlg;

    private final MacAlg macAlg;

    private final byte[] selfMacKey;

    private final byte[] peerMackey;

    private final byte[] selfCryptoKey;

    private final byte[] selfCryptoKeyIv;

    private final byte[] peerCryptoKey;

    private final byte[] peerCryptoIv;

    public TLSTextCryptoParameters getReadTLSTextCryptoParameters() {
        return new TLSTextCryptoParameters(bulkCipherAlg, macAlg, peerMackey, peerCryptoKey, peerCryptoIv);
    }

    public TLSTextCryptoParameters getWriteTLSTextCryptoParameters() {
        return new TLSTextCryptoParameters(bulkCipherAlg, macAlg, selfMacKey, selfCryptoKey, selfCryptoKeyIv);
    }

    public MacAlg getMacAlg() {
        return macAlg;
    }

    public TLSCryptoParameters(BulkCipherAlg bulkCipherAlg, MacAlg macAlg, byte[] selfMacKey, byte[] peerMackey, byte[] selfCryptoKey, byte[] selfCryptoKeyIv, byte[] peerCryptoKey, byte[] peerCryptoIv) {
        this.bulkCipherAlg = bulkCipherAlg;
        this.macAlg = macAlg;
        this.selfMacKey = selfMacKey;
        this.peerMackey = peerMackey;
        this.selfCryptoKey = selfCryptoKey;
        this.selfCryptoKeyIv = selfCryptoKeyIv;
        this.peerCryptoKey = peerCryptoKey;
        this.peerCryptoIv = peerCryptoIv;
    }

    public static final class TLSCryptoParametersBuilder {
        private BulkCipherAlg bulkCipherAlg;
        private MacAlg macAlg;
        private byte[] selfMacKey;
        private byte[] peerMackey;
        private byte[] selfCryptoKey;
        private byte[] selfCryptoKeyIv;
        private byte[] peerCryptoKey;
        private byte[] peerCryptoIv;

        private TLSCryptoParametersBuilder() {
        }

        public static TLSCryptoParametersBuilder aTLSCryptoParameters() {
            return new TLSCryptoParametersBuilder();
        }

        public TLSCryptoParametersBuilder withBulkCipherAlg(BulkCipherAlg bulkCipherAlg) {
            this.bulkCipherAlg = bulkCipherAlg;
            return this;
        }

        public TLSCryptoParametersBuilder withMacAlg(MacAlg macAlg) {
            this.macAlg = macAlg;
            return this;
        }

        public TLSCryptoParametersBuilder withSelfMacKey(byte[] selfMacKey) {
            this.selfMacKey = selfMacKey;
            return this;
        }

        public TLSCryptoParametersBuilder withPeerMackey(byte[] peerMackey) {
            this.peerMackey = peerMackey;
            return this;
        }

        public TLSCryptoParametersBuilder withSelfCryptoKey(byte[] selfCryptoKey) {
            this.selfCryptoKey = selfCryptoKey;
            return this;
        }

        public TLSCryptoParametersBuilder withSelfCryptoKeyIv(byte[] selfCryptoKeyIv) {
            this.selfCryptoKeyIv = selfCryptoKeyIv;
            return this;
        }

        public TLSCryptoParametersBuilder withPeerCryptoKey(byte[] peerCryptoKey) {
            this.peerCryptoKey = peerCryptoKey;
            return this;
        }

        public TLSCryptoParametersBuilder withPeerCryptoIv(byte[] peerCryptoIv) {
            this.peerCryptoIv = peerCryptoIv;
            return this;
        }

        public TLSCryptoParameters build() {
            return new TLSCryptoParameters(bulkCipherAlg, macAlg, selfMacKey, peerMackey, selfCryptoKey, selfCryptoKeyIv, peerCryptoKey, peerCryptoIv);
        }
    }
}
