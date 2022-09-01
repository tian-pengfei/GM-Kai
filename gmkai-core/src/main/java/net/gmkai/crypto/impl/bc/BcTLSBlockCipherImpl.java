package net.gmkai.crypto.impl.bc;

import net.gmkai.crypto.impl.TLSBlockCipherImpl;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import java.io.IOException;

public class BcTLSBlockCipherImpl implements TLSBlockCipherImpl {

    private final boolean isEncrypting;
    private final BlockCipher cipher;

    private KeyParameter key;

    BcTLSBlockCipherImpl(BlockCipher cipher, boolean isEncrypting) {
        this.cipher = cipher;
        this.isEncrypting = isEncrypting;
    }

    @Override
    public void setKey(byte[] key, int keyOff, int keyLen) throws IOException {
        this.key = new KeyParameter(key);
    }

    @Override
    public void init(byte[] iv, int ivOff, int ivLen) throws IOException {
        cipher.init(isEncrypting, new ParametersWithIV(key, iv, ivOff, ivLen));
    }

    @Override
    public int doFinal(byte[] input, int inputOffset, int inputLength, byte[] output, int outputOffset) throws IOException {
        int blockSize = cipher.getBlockSize();

        for (int i = 0; i < inputLength; i += blockSize) {
            cipher.processBlock(input, inputOffset + i, output, outputOffset + i);
        }

        return inputLength;
    }

    @Override
    public int getBlockSize() {
        return cipher.getBlockSize();
    }
}
