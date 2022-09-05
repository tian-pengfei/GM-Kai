package net.gmkai.crypto.impl;

import net.gmkai.TLSText;
import net.gmkai.crypto.TLSCipher;

import java.io.IOException;

public class TLSNullCipher implements TLSCipher {

    public final static TLSNullCipher NULL_CIPHER = new TLSNullCipher();

    private TLSNullCipher() {
    }

    @Override
    public TLSText decryptTLSText(long seqNo, TLSText encryptedText) {
        return encryptedText;
    }

    @Override
    public void updateDecryptKey(byte[] key, int keyOff, int keyLen) throws IOException {

    }

    @Override
    public TLSText encryptTLSText(long seqNo, TLSText plaintext) {
        return plaintext;
    }

    @Override
    public void updateEncryptKey(byte[] key, int keyOff, int keyLen) throws IOException {

    }
}
