package net.gmkai.crypto.impl.bc;

import net.gmkai.crypto.AsymmetricBlockPadding;
import net.gmkai.crypto.TLSRSACipher;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.RSABlindedEngine;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.RSAKeyParameters;

import javax.net.ssl.SSLException;
import java.io.IOException;
import java.security.Key;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public class BcTLSRSACipher extends TLSRSACipher {

    private final AsymmetricBlockCipher asymmetricBlockCipher;

    public BcTLSRSACipher(boolean forEncryption, AsymmetricBlockPadding blockPadding, Key key) {

        this(forEncryption, blockPadding, key, new SecureRandom());
    }

    public BcTLSRSACipher(boolean forEncryption, AsymmetricBlockPadding blockPadding, Key key, SecureRandom secureRandom) {

        super(forEncryption, blockPadding, key);

        if (blockPadding == AsymmetricBlockPadding.PKCS1Padding) {

            asymmetricBlockCipher = new PKCS1Encoding(new RSABlindedEngine());
            asymmetricBlockCipher.init(forEncryption,
                    new ParametersWithRandom(getRSAKeyParameters(key), secureRandom));
            return;
        }

        asymmetricBlockCipher = new RSAEngine();
    }

    @Override
    public int getInputBlockSize() {
        return asymmetricBlockCipher.getInputBlockSize();
    }

    @Override
    public int getOutputBlockSize() {
        return asymmetricBlockCipher.getOutputBlockSize();
    }

    @Override
    public byte[] processBlock(byte[] in, int inOff, int len) throws IOException {
        try {
            return asymmetricBlockCipher.processBlock(in, inOff, len);
        } catch (InvalidCipherTextException e) {
            throw new SSLException(e.getMessage(), e);
        }
    }

    private RSAKeyParameters getRSAKeyParameters(Key key) {

        if (key instanceof RSAPrivateKey) {

            return new RSAKeyParameters(true, ((RSAPrivateKey) key).getModulus(), ((RSAPrivateKey) key).getPrivateExponent());
        }

        if (key instanceof RSAPublicKey) {
            return new RSAKeyParameters(false, ((RSAPublicKey) key).getModulus(), ((RSAPublicKey) key).getPublicExponent());
        }

        throw new RuntimeException();
    }
}
