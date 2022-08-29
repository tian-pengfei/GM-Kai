package net.gmkai.crypto;

public interface TLSCrypto {

    TLSHMac createHMAC(MacAlg macAlg);
}
