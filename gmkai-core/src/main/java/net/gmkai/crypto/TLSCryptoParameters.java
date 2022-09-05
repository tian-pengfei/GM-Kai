package net.gmkai.crypto;

public class TLSCryptoParameters {


    private final CipherAlg cipherAlg;

    private final MacAlg macAlg;

    private final byte[] selfMacKey;

    private final byte[] peerMackey;

    private final byte[] selfCryptoKey;

    private final byte[] selfCryptoKeyIv;

    private final byte[] peerCryptoKey;

    private final byte[] peerCryptoIv;

    public byte[] getSelfMacKey() {
        return selfMacKey;
    }

    public byte[] getPeerMackey() {
        return peerMackey;
    }

    public byte[] getSelfCryptoKey() {
        return selfCryptoKey;
    }

    public byte[] getPeerCryptoKey() {
        return peerCryptoKey;
    }

    public byte[] getSelfCryptoIv() {
        return selfCryptoKeyIv;
    }

    public byte[] getPeerCryptoIv() {
        return peerCryptoIv;
    }

    public CipherAlg getCipherAlg() {
        return cipherAlg;
    }

    public MacAlg getMacAlg() {
        return macAlg;
    }

    public byte[] getSelfCryptoKeyIv() {
        return selfCryptoKeyIv;
    }

    public TLSCryptoParameters(CipherAlg cipherAlg, MacAlg macAlg, byte[] selfMacKey, byte[] peerMackey, byte[] selfCryptoKey, byte[] selfCryptoKeyIv, byte[] peerCryptoKey, byte[] peerCryptoIv) {
        this.cipherAlg = cipherAlg;
        this.macAlg = macAlg;
        this.selfMacKey = selfMacKey;
        this.peerMackey = peerMackey;
        this.selfCryptoKey = selfCryptoKey;
        this.selfCryptoKeyIv = selfCryptoKeyIv;
        this.peerCryptoKey = peerCryptoKey;
        this.peerCryptoIv = peerCryptoIv;
    }

    public static final class TLSCryptoParametersBuilder {
        private CipherAlg cipherAlg;
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

        public TLSCryptoParametersBuilder withCipherAlg(CipherAlg cipherAlg) {
            this.cipherAlg = cipherAlg;
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
            return new TLSCryptoParameters(cipherAlg, macAlg, selfMacKey, peerMackey, selfCryptoKey, selfCryptoKeyIv, peerCryptoKey, peerCryptoIv);
        }
    }
}
