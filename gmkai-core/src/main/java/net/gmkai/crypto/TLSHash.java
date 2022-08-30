package net.gmkai.crypto;

public interface TLSHash {

    void update(byte[] input, int inOff, int length);

    byte[] calculateHash();

    void calculateHash(byte[] output, int outOff);

    void reset();

}
