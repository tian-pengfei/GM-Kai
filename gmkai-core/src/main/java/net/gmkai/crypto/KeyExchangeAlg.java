package net.gmkai.crypto;

public enum KeyExchangeAlg {


    K_ECDHE("ECDHE", "EC", SignatureAndHashAlg.SM2SIG_SM3),

    K_ECC("ECC", "EC", SignatureAndHashAlg.SM2SIG_SM3),

    K_RSA("RSA", "RSA", SignatureAndHashAlg.RSA_SHA256);

    final public String name;

    public final String keyType;

    final public SignatureAndHashAlg signatureAndHashAlg;


    KeyExchangeAlg(String name, String keyType, SignatureAndHashAlg signatureAndHashAlg) {
        this.name = name;
        this.keyType = keyType;
        this.signatureAndHashAlg = signatureAndHashAlg;
    }
}
