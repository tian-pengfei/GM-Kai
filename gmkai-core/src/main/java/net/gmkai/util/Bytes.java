package net.gmkai.util;

public class Bytes {

    public static byte[] concat(byte[]... arrays) {
        return com.google.common.primitives.Bytes.concat(arrays);
    }
}
