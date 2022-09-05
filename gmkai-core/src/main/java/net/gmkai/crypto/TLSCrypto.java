package net.gmkai.crypto;

import javax.net.ssl.SSLException;
import java.io.IOException;

public interface TLSCrypto {

    TLSHMac createHMAC(MacAlg macAlg);

    TLSHash createHash(HashAlg hashAlg);

    TLSBlockCipher createTLSBlockCipher(TLSCryptoParameters cryptoParameters) throws IOException;

    default TLSCipher createTLSCipher(TLSCryptoParameters cryptoParameters) throws IOException {

        if (cryptoParameters.getCipherAlg().cipherType == TLSCipherType.BLOCK_CIPHER) {
            return createTLSBlockCipher(cryptoParameters);
        }
        throw new SSLException("未支持其他类型加密");
    }
}
