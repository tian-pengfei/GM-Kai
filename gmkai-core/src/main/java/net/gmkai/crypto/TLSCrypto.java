package net.gmkai.crypto;

public interface TLSCrypto {

    TLSHMac createHMAC(MacAlg macAlg);

    TLSHash createHash(HashAlg hashAlg);
}
