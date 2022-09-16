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
import java.security.SecureRandom;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public class BcTLSRSACipher extends TLSRSACipher {

    private final AsymmetricBlockCipher asymmetricBlockCipher;

    public BcTLSRSACipher(boolean forEncryption, AsymmetricBlockPadding blockPadding, RSAKey rsaKey) {

        this(forEncryption, blockPadding, rsaKey, new SecureRandom());
    }

    public BcTLSRSACipher(boolean forEncryption, AsymmetricBlockPadding blockPadding, RSAKey rsaKey, SecureRandom secureRandom) {

        super(forEncryption, blockPadding, rsaKey);


        if (blockPadding == AsymmetricBlockPadding.PKCS1Padding) {

            asymmetricBlockCipher = new PKCS1Encoding(new RSABlindedEngine());
            asymmetricBlockCipher.init(forEncryption,
                    new ParametersWithRandom(getRSAKeyParameters(rsaKey), secureRandom));
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

    private RSAKeyParameters getRSAKeyParameters(RSAKey rsaKey) {

        if (rsaKey instanceof RSAPrivateKey) {

            return new RSAKeyParameters(true, rsaKey.getModulus(), ((RSAPrivateKey) rsaKey).getPrivateExponent());
        }

        if (rsaKey instanceof RSAPublicKey) {
            return new RSAKeyParameters(false, rsaKey.getModulus(), ((RSAPublicKey) rsaKey).getPublicExponent());
        }

        throw new RuntimeException();
    }
}
