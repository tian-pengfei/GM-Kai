package net.gmkai.crypto.impl.bc;

import net.gmkai.crypto.impl.TLSBlockCipherImplTest;
import org.bouncycastle.crypto.engines.SM4Engine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;

import java.io.IOException;

public class BcTLSBlockCipherImplTest extends TLSBlockCipherImplTest {


    public BcTLSBlockCipherImplTest() throws IOException {

        super(new BcTLSBlockCipherImpl(new CBCBlockCipher(new SM4Engine()), true),
                new BcTLSBlockCipherImpl(new CBCBlockCipher(new SM4Engine()), false));
    }
}
