package net.gmkai.crypto.impl.bc;


import net.gmkai.crypto.impl.TLSSM2CipherTest;

public class BcTLSSM2CipherTest extends TLSSM2CipherTest {

    protected BcTLSSM2CipherTest() {
        super(new BcTLSCrypto());
    }
}
