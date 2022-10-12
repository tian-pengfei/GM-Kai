package net.gmkai;

import java.security.PublicKey;
import java.security.cert.X509Certificate;

public class TLCPX509Credentials {

    private final X509Certificate[] chain;

    private final PublicKey sigPubKey;

    private final PublicKey encPubKey;

    public TLCPX509Credentials(X509Certificate[] chain, PublicKey sigPubKey, PublicKey encPubKey) {
        this.chain = chain;
        this.sigPubKey = sigPubKey;
        this.encPubKey = encPubKey;
    }


    public X509Certificate[] getChain() {
        return chain;
    }

    public PublicKey getSigPubKey() {
        return sigPubKey;
    }

    public PublicKey getEncPubKey() {
        return encPubKey;
    }
}
