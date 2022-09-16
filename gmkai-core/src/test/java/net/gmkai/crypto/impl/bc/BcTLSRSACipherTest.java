package net.gmkai.crypto.impl.bc;

import net.gmkai.crypto.impl.TLSRSACipherTest;

public class BcTLSRSACipherTest extends TLSRSACipherTest {

    protected BcTLSRSACipherTest() {
        super(new BcTLSCrypto());
    }
}
