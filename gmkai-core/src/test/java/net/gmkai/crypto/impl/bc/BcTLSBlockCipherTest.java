package net.gmkai.crypto.impl.bc;

import net.gmkai.crypto.impl.TLSBlockCipherTest;
import org.bouncycastle.crypto.engines.SM4Engine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;

import java.io.IOException;

public class BcTLSBlockCipherTest extends TLSBlockCipherTest {


    public BcTLSBlockCipherTest() throws IOException {

        super(new BcTLSBlockCipher(new CBCBlockCipher(new SM4Engine()), true),
                new BcTLSBlockCipher(new CBCBlockCipher(new SM4Engine()), false));
    }
}
