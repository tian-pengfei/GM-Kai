package net.gmkai.crypto;

public interface TLSAsymmetricBlockCipher extends TLSAsymmetricCipher {


    int getInputBlockSize();

    int getOutputBlockSize();

}
