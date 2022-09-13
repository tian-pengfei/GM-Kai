package net.gmkai.crypto;

public enum SignatureAlg {
    SIG_SM2(true),

    SIG_RSA(false);

    final boolean isEc;

    SignatureAlg(boolean isEc) {
        this.isEc = isEc;
    }

    public boolean isEC() {
        return isEc;
    }
}
