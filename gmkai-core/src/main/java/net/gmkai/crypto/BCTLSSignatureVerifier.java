package net.gmkai.crypto;

import org.bouncycastle.crypto.Signer;

import java.util.Arrays;

public class BCTLSSignatureVerifier implements TLSSignatureVerifier {

    private final Signer signer;

    public BCTLSSignatureVerifier(Signer signer) {
        this.signer = signer;
    }

    @Override
    public void addData(byte[]... datas) {
        Arrays.stream(datas).forEach(data -> {
            signer.update(data, 0, data.length);
        });
    }

    @Override
    public boolean verifySignature(byte[] signature) {
        return signer.verifySignature(signature);
    }
}
