package com.tianpengfei.gmkai.util;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

public interface Bytes {

    static byte getByte(int d) throws IOException {
        return (byte) d;
    }

    static byte[] get2Bytes(int d) {

        return new byte[]{(byte) (d >>> 8 & 0xFF), (byte) d};
    }

    static byte[] get3Bytes(int d) {

        return new byte[]{(byte) (d >>> 16 & 0xFF), (byte) (d >>> 8 & 0xFF), (byte) d};
    }

    static byte[] get4Bytes(int d) {
        return new byte[]{(byte) (d >>> 24 & 0xFF), (byte) (d >>> 16 & 0xFF), (byte) (d >>> 8 & 0xFF), (byte) d};
    }


    static byte[] combine(byte[]... datas) throws IOException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        for (byte[] data : datas) {
            outputStream.write(data);
        }
        return outputStream.toByteArray();
    }
}
