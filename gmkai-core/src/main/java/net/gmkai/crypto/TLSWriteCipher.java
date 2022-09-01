package net.gmkai.crypto;

import net.gmkai.TLSText;

import java.io.IOException;

public interface TLSWriteCipher extends TLSKeyUpdatable {

    TLSText encryptTLSText(long seqNo, TLSText plaintext) throws IOException;

    void updateEncryptKey(byte[] key, int keyOff, int keyLen) throws IOException;

}
