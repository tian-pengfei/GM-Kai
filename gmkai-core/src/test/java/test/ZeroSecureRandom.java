package test;

import java.security.SecureRandom;
import java.util.Arrays;

public class ZeroSecureRandom extends SecureRandom {


    @Override
    public void nextBytes(byte[] bytes) {
        Arrays.fill(bytes, (byte) 0);
    }


    @Override
    public long nextLong() {
        return 0;
    }

    @Override
    public byte[] generateSeed(int numBytes) {
        return new byte[numBytes];
    }
}
