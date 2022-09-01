package net.gmkai.util;

import org.bouncycastle.util.encoders.Hex;

public class Hexs {

    public static byte[] decode(
            String data) {
        return Hex.decode(data);
    }

    public static String toHexString(
            byte[] data) {
        return Hex.toHexString(data);
    }
}
