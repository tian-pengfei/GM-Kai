package net.gmkai;

import java.security.cert.X509Certificate;

public final class KeyUsage {

    public static final KeyUsage digitalSignature = new KeyUsage(0b100000000);

    public static final KeyUsage nonRepudiation = new KeyUsage(0b010000000);

    public static final KeyUsage keyEncipherment = new KeyUsage(0b001000000);

    public static final KeyUsage dataEncipherment = new KeyUsage(0b000100000);

    public static final KeyUsage keyAgreement = new KeyUsage(0b000010000);

    public static final KeyUsage keyCertSign = new KeyUsage(0b000001000);

    public static final KeyUsage cRLSign = new KeyUsage(0b000000100);

    public static final KeyUsage encipherOnly = new KeyUsage(0b000000010);

    public static final KeyUsage decipherOnly = new KeyUsage(0b000000001);

    private final int bits;

    public KeyUsage(int bits) {
        bits &= 0b111111111;
        this.bits = bits;
    }

    public KeyUsage(X509Certificate certificate) {
        this(certificate.getKeyUsage());
    }

    private KeyUsage(boolean[] keyBits) {
        int val = 0;

        for (int i = 0; i < 9; i++) {
            if (!keyBits[i]) continue;
            val |= (1 << (8 - i));
        }
        this.bits = val;
    }

    public boolean verify(KeyUsage... keyUsages) {

        for (KeyUsage keyUsage : keyUsages) {
            if (keyUsage.bits != (keyUsage.bits & this.bits)) {
                return false;
            }
        }
        return true;
    }

    public KeyUsage add(KeyUsage... keyUsages) {
        int newBits = this.bits;
        for (KeyUsage keyUsage : keyUsages) {
            newBits |= keyUsage.bits;
        }
        return new KeyUsage(newBits);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        KeyUsage keyUsage = (KeyUsage) o;
        return bits == keyUsage.bits;
    }
}
