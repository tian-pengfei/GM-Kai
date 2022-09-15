package net.gmkai.crypto;


import net.gmkai.TLSText;

import java.io.IOException;

public interface TLSTextCipher {

    TLSText processTLSText(TLSText tlsText) throws IOException;

}
