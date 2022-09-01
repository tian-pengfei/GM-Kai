package net.gmkai.crypto;

import java.io.IOException;

public interface TLSCrypto {

    TLSHMac createHMAC(MacAlg macAlg);

    TLSHash createHash(HashAlg hashAlg);

    TLSBlockCipher createTLSBlockCipher(TLSCryptoParameters cryptoParameters, CipherAlg cipherAlg, MacAlg macAlg) throws IOException;
}
