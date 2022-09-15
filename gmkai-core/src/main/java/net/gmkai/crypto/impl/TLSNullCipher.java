package net.gmkai.crypto.impl;

import net.gmkai.TLSText;
import net.gmkai.crypto.TLSTextCipher;

import java.io.IOException;

public class TLSNullCipher implements TLSTextCipher {

    public final static TLSNullCipher NULL_CIPHER = new TLSNullCipher();

    private TLSNullCipher() {
    }


    @Override
    public TLSText processTLSText(TLSText tlsText) throws IOException {
        return tlsText;
    }
}
