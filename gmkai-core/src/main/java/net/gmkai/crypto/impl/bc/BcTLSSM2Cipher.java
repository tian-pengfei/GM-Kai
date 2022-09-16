package net.gmkai.crypto.impl.bc;

import net.gmkai.crypto.TLSSM2Cipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;

import javax.net.ssl.SSLException;
import java.io.IOException;
import java.security.*;

public class BcTLSSM2Cipher extends TLSSM2Cipher {

    private final SM2Engine sm2Engine;

    public BcTLSSM2Cipher(boolean forEncryption, Key key, SecureRandom secureRandom) throws SSLException {
        sm2Engine = new SM2Engine();
        AsymmetricKeyParameter keyParameter = generateKeyParameters(key);
        CipherParameters parameters = forEncryption ? new ParametersWithRandom(keyParameter, secureRandom) : keyParameter;
        sm2Engine.init(forEncryption, parameters);
    }

    public BcTLSSM2Cipher(boolean forEncryption, Key key) throws SSLException {
        this(forEncryption, key, new SecureRandom());
    }

    @Override
    public byte[] processBlock(byte[] in, int inOff, int len) throws IOException {
        try {
            return sm2Engine.processBlock(in, inOff, len);
        } catch (InvalidCipherTextException e) {
            throw new SSLException(e.getMessage(), e);
        }
    }

    private AsymmetricKeyParameter generateKeyParameters(Key key) throws SSLException {
        try {
            if (key instanceof PrivateKey) {
                return ECUtil.generatePrivateKeyParameter((PrivateKey) key);
            }
            return ECUtil.generatePublicKeyParameter((PublicKey) key);
        } catch (InvalidKeyException e) {
            throw new SSLException(e.getMessage(), e);
        }
    }
}
