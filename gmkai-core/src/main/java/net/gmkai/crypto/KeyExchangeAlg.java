package net.gmkai.crypto;

public enum KeyExchangeAlg {

    ECDHE("ECDHE"),
    ECC("ECC"),
    RSA("RSA");

    final public String name;


    KeyExchangeAlg(String name) {
        this.name = name;
    }
}
