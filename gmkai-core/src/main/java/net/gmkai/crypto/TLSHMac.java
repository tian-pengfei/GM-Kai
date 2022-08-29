package net.gmkai.crypto;

public interface TLSHMac {

    void setKey(byte[] key, int keyOff, int keyLen);

    void update(byte[] input, int inOff, int length);

    byte[] calculateMAC();

    void calculateMAC(byte[] output, int outOff);

    int getMacLength();

    void reset();

    int getInternalBlockSize();


}
