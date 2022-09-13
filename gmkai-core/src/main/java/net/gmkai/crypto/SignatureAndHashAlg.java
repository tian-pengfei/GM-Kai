package net.gmkai.crypto;

public enum SignatureAndHashAlg {

    SM2SIG_SM3("sm2sig_sm3", 0x0708, "SM3withSM2", SignatureAlg.SIG_SM2, HashAlg.H_SM3),

    RSA_SHA256("rsa_sha256", 0x0708, "SHA256withRSA", SignatureAlg.SIG_RSA, HashAlg.H_SHA256);

    final public int id;

    final public String name;

    final public String jceName;

    final public SignatureAlg signAlg;

    final public HashAlg hashAlg;

    SignatureAndHashAlg(String name, int id, String jceName, SignatureAlg signAlg, HashAlg hashAlg) {
        this.jceName = jceName;
        this.hashAlg = hashAlg;
        this.name = name;
        this.signAlg = signAlg;
        this.id = id;
    }
}
