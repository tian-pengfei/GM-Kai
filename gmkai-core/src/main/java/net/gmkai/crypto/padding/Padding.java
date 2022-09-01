package net.gmkai.crypto.padding;

import javax.net.ssl.SSLException;

public interface Padding {


    byte[] getPaddingBytes(int dataLen,int blockSize);

    int getPaddingCount(byte[] paddedData , int dataOff, int dataLen) throws SSLException;

}
