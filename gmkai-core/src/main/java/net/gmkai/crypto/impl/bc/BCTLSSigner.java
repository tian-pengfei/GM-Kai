package net.gmkai.crypto.impl.bc;

import net.gmkai.crypto.TLSSigner;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Signer;

import javax.net.ssl.SSLException;
import java.io.IOException;
import java.util.Arrays;

public class BCTLSSigner implements TLSSigner {

    private final Signer signer;

    public BCTLSSigner(Signer signer) {
        this.signer = signer;
    }

    @Override
    public void addData(byte[]... datas) {
        Arrays.stream(datas).
                forEach(data -> signer.update(data, 0, data.length));
    }

    @Override
    public byte[] getSignature() throws IOException {

        try {
            return signer.generateSignature();
        } catch (CryptoException e) {
            throw new SSLException(e.getMessage(), e);
        }
    }
}
