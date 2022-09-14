package net.gmkai.crypto;

public enum KeyExchangeAlg {


    K_ECDHE("ECDHE", SignatureAndHashAlg.SM2SIG_SM3),

    K_ECC("ECC", SignatureAndHashAlg.SM2SIG_SM3),

    K_RSA("RSA", SignatureAndHashAlg.RSA_SHA256);

    final public String name;

    final public SignatureAndHashAlg signatureAndHashAlg;


    KeyExchangeAlg(String name, SignatureAndHashAlg signatureAndHashAlg) {
        this.name = name;
        this.signatureAndHashAlg = signatureAndHashAlg;
    }
}
