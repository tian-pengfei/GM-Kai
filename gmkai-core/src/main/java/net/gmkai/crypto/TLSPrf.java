package net.gmkai.crypto;

import net.gmkai.util.Bytes;

import javax.net.ssl.SSLException;
import java.nio.charset.StandardCharsets;

public class TLSPrf {

    private final TLSHMac tlshMac;

    TLSPrf(TLSHMac tlshMac) {
        this.tlshMac = tlshMac;
    }

    public byte[] prf(byte[] secret, String label, byte[] seed, int length) throws SSLException {

        byte[] labelSeed = Bytes.concat(label.getBytes(StandardCharsets.UTF_8), seed);
        byte[] result = new byte[length];
        try {
            hmacHash(secret, labelSeed, result);
        } catch (Exception e) {
            throw new SSLException(e.getMessage(), e);
        }

        return result;
    }

    private void hmacHash(byte[] secret, byte[] seed, byte[] output)
            throws IllegalStateException {

        tlshMac.setKey(secret, 0, secret.length);
        byte[] a = seed;

        int macSize = tlshMac.getMacLength();

        byte[] b1 = new byte[macSize];
        byte[] b2 = new byte[macSize];

        int pos = 0;
        while (pos < output.length) {
            tlshMac.update(a, 0, a.length);
            tlshMac.calculateMAC(b1, 0);
            a = b1;
            tlshMac.update(a, 0, a.length);
            tlshMac.update(seed, 0, seed.length);
            tlshMac.calculateMAC(b2, 0);
            System.arraycopy(b2, 0, output, pos, Math.min(macSize, output.length - pos));
            pos += macSize;
        }

    }
}
