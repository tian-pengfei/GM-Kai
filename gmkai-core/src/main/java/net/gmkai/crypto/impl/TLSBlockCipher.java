package net.gmkai.crypto.impl;

import java.io.IOException;


public interface TLSBlockCipher {

    void setKey(byte[] key, int keyOff, int keyLen) throws IOException;

    void init(byte[] iv, int ivOff, int ivLen) throws IOException;

    int doFinal(byte[] input, int inputOffset, int inputLength, byte[] output, int outputOffset) throws IOException;

    int getBlockSize();
}
