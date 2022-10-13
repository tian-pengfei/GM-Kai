package net.gmkai;

public enum ClientCertificateType {

    RSA_SIGN((byte) 0x01, "rsa_sign", "RSA"),

    ECDSA_SIGN((byte) 0x40, "ecdsa_sign", "EC");

    public final byte id;

    public final String name;

    public final String keyAlgorithm;

    ClientCertificateType(byte id, String name,
                          String keyAlgorithm) {
        this.id = id;
        this.name = name;
        this.keyAlgorithm = keyAlgorithm;

    }
}
