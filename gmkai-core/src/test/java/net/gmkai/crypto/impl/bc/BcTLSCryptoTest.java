package net.gmkai.crypto.impl.bc;

import net.gmkai.crypto.impl.TLSCryptoTest;

public class BcTLSCryptoTest extends TLSCryptoTest {

    public BcTLSCryptoTest() {
        super(new BcTLSCrypto());
    }
}
