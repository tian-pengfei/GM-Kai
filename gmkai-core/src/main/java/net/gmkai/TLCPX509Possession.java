package net.gmkai;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public class TLCPX509Possession {

    private final X509Certificate[] chain;

    private final PrivateKey sigPriKey;

    private final PrivateKey encPriKey;

    public TLCPX509Possession(X509Certificate[] chain, PrivateKey sigPriKey, PrivateKey encPriKey) {
        this.chain = chain;
        this.sigPriKey = sigPriKey;
        this.encPriKey = encPriKey;
    }

    public PrivateKey getSigPriKey() {
        return sigPriKey;
    }

    public PrivateKey getEncPriKey() {
        return encPriKey;
    }

    public X509Certificate[] getChain() {
        return chain;
    }
}
