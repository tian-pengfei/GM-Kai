package net.gmkai.crypto.impl.bc;

import net.gmkai.BCTLSSigner;
import net.gmkai.crypto.*;
import net.gmkai.crypto.padding.Padding;
import net.gmkai.crypto.padding.TLSPadding;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.engines.SM4Engine;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.signers.RSADigestSigner;
import org.bouncycastle.crypto.signers.SM2Signer;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;

import javax.net.ssl.SSLException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public class BcTLSCrypto implements TLSCrypto {


    @Override
    public TLSHMac createHMAC(MacAlg macAlg) {

        switch (macAlg) {
            case M_SM3:
                return new BcTLSHMac(new HMac(new SM3Digest()));
            case M_SHA256:
                return new BcTLSHMac(new HMac(new SHA256Digest()));
            default:
                throw new IllegalStateException("Unexpected value: " + macAlg);
        }

    }

    @Override
    public TLSHash createHash(HashAlg hashAlg) {

        return new BcTLSHash(createDigest(hashAlg));
    }

    @Override
    public TLSTextBlockCipher createTLSTextBlockCipher(boolean forEncryption, TLSTextCryptoParameters tlsTextCryptoParameters) throws IOException {

        if (tlsTextCryptoParameters.getBulkCipherAlg().cipherType != TLSCipherType.BLOCK_CIPHER) {
            throw new RuntimeException();
        }
        BcTLSBlockCipher tlsBlockCipher = new BcTLSBlockCipher(createBlockCipher(tlsTextCryptoParameters.getBulkCipherAlg()), forEncryption);

        Padding padding = new TLSPadding();

        return new TLSTextBlockCipher(forEncryption, tlsTextCryptoParameters,
                tlsBlockCipher, createHMAC(tlsTextCryptoParameters.getMacAlg()),
                tlsTextCryptoParameters.getBulkCipherAlg().cipherKeySize, padding);
    }


    @Override
    public TLSSigner getTLSSigner(PrivateKey privateKey, SignatureAndHashAlg sigAndHashAlg) {
        try {
            Signer signer = createSigner(sigAndHashAlg);
            CipherParameters param;
            param = CreateSignCipherParameters(privateKey, sigAndHashAlg.signAlg);
            signer.init(true, param);
            return new BCTLSSigner(signer);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e.getMessage(), e);
        }
    }


    @Override
    public TLSSignatureVerifier getTLSSignatureVerifier(PublicKey publicKey, SignatureAndHashAlg sigAndHashAlg) {
        try {

            Signer signer = createSigner(sigAndHashAlg);
            CipherParameters param;

            //这种也是可以的
//            Signature signature = Signature.getInstance("SM3withSM2", BouncyCastleProvider.PROVIDER_NAME);

            param = CreateSignCipherParameters(publicKey, sigAndHashAlg.signAlg);
            signer.init(false, param);
            return new BCTLSSignatureVerifier(signer);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    @Override
    public TLSRSACipher getTLSRSACipher(boolean forEncryption, AsymmetricBlockPadding blockPadding, Key key) {
        return new BcTLSRSACipher(forEncryption, blockPadding, key);
    }

    @Override
    public TLSSM2Cipher getTLSSM2Cipher(boolean forEncryption, Key key) throws SSLException {
        return new BcTLSSM2Cipher(forEncryption, key);
    }


    private CipherParameters CreateSignCipherParameters(PrivateKey privateKey, SignatureAlg signAlg) throws InvalidKeyException {

        if (privateKey instanceof RSAPrivateKey && signAlg == SignatureAlg.SIG_RSA) {
            RSAPrivateKey _private = (RSAPrivateKey) privateKey;
            return new RSAKeyParameters(true, _private.getModulus(), _private.getPrivateExponent());
        }

        if (privateKey instanceof ECPrivateKey && signAlg.isEC()) {
            return ECUtil.generatePrivateKeyParameter(privateKey);
        }

        throw new RuntimeException();
    }

    private CipherParameters CreateSignCipherParameters(PublicKey publicKey, SignatureAlg signAlg) throws InvalidKeyException {

        if (publicKey instanceof RSAPublicKey && signAlg == SignatureAlg.SIG_RSA) {
            RSAPublicKey _publicKey = (RSAPublicKey) publicKey;
            return new RSAKeyParameters(false, _publicKey.getModulus(), _publicKey.getPublicExponent());
        }

        if (publicKey instanceof ECPublicKey && signAlg.isEC()) {
            return ECUtil.generatePublicKeyParameter(publicKey);
        }
        throw new RuntimeException();
    }

    BlockCipher createBlockCipher(BulkCipherAlg bulkCipherAlg) {
        switch (bulkCipherAlg) {
            case SM4_CBC:
                return new CBCBlockCipher(new SM4Engine());
            case SM4_GCM:
                throw new UnsupportedOperationException();
            default:
                throw new IllegalStateException("Unexpected value: " + bulkCipherAlg);
        }

    }

    private Signer createSigner(SignatureAndHashAlg signAndHashAlg) {

        Digest digest = createDigest(signAndHashAlg.hashAlg);
        SignatureAlg signAlg = signAndHashAlg.signAlg;
        switch (signAlg) {
            case SIG_SM2:
                return new SM2Signer(digest);
            case SIG_RSA:
                return new RSADigestSigner(digest);
            default:
                throw new IllegalStateException("Unexpected value: " + signAlg);
        }

    }

    private Digest createDigest(HashAlg hashAlg) {

        switch (hashAlg) {
            case H_SM3:
                return new SM3Digest();
            case H_SHA256:
                return new SHA256Digest();
            default:
                throw new IllegalStateException("Unexpected value: " + hashAlg);
        }
    }


}
