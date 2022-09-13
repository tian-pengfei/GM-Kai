package net.gmkai.crypto;

public interface TLSSignatureVerifier {

    void addData(byte[]... datas);

    boolean verifySignature(byte[] signature);
}
