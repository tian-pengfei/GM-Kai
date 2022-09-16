package net.gmkai.crypto;

import javax.net.ssl.SSLException;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAKey;

public interface TLSCrypto {

    TLSHMac createHMAC(MacAlg macAlg);

    TLSHash createHash(HashAlg hashAlg);

    TLSTextBlockCipher createTLSTextBlockCipher(boolean forEncryption, TLSTextCryptoParameters tlsTextCryptoParameters) throws IOException;

    default TLSTextCipher createTLSTextCipher(boolean forEncryption, TLSTextCryptoParameters tlsTextCryptoParameters) throws IOException {

        if (tlsTextCryptoParameters.getBulkCipherAlg().cipherType == TLSCipherType.BLOCK_CIPHER) {
            return createTLSTextBlockCipher(forEncryption, tlsTextCryptoParameters);
        }

        throw new SSLException("未支持其他类型加密");
    }

    TLSSigner getTLSSigner(PrivateKey privateKey, SignatureAndHashAlg sigAndHashAlg);


    TLSSignatureVerifier getTLSSignatureVerifier(PublicKey publicKey, SignatureAndHashAlg sigAndHashAlg);

    TLSRSACipher getTLSRSACipher(boolean forEncryption, AsymmetricBlockPadding blockPadding, RSAKey rsaKey);
}
