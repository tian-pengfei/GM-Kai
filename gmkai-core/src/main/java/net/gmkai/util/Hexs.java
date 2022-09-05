package net.gmkai.util;

import org.bouncycastle.util.encoders.Hex;

public interface Hexs {

    static byte[] decode(
            String data) {
        return Hex.decode(data);
    }

    static String toHexString(
            byte[] data) {
        return Hex.toHexString(data);
    }
}
