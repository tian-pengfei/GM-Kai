package net.gmkai.crypto;

import java.io.IOException;

public interface TLSAsymmetricCipher {

    byte[] processBlock(byte[] in, int inOff, int len)
            throws IOException;
}
