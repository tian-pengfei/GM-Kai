package net.gmkai.crypto;

import net.gmkai.TLSText;

import java.io.IOException;

public interface TLSReadCipher {

    TLSText decryptTLSText(long seqNo, TLSText encryptedText) throws IOException;

    void updateDecryptKey(byte[] key, int keyOff, int keyLen) throws IOException;

}
