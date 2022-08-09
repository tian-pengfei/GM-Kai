package com.tianpengfei.gmkai;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Provider;
import java.security.Security;

public class GMKaiProvider extends Provider {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public GMKaiProvider() {

        super(PROVIDER_NAME, 1.0, "Tian Peng Fei's GMProvider");

        put("SSLContext.TLCP", GMSSLContextSpi.class.getName());
        put("KeyManagerFactory.GMKaiX509", GMX509KeyManagerFactory.class.getName());
        put("TrustManagerFactory.GMKaiX509", GMX509TrustManagerFactory.class.getName());
    }


    public static final String PROVIDER_NAME = "GMKai";
}
