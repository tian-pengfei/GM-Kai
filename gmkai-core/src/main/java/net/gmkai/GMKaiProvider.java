package net.gmkai;

import java.security.Provider;

public class GMKaiProvider extends Provider {

    public static final String PROVIDER_NAME = "GMKAIJSSE";

    private static final double PROVIDER_VERSION = 0.1;

    private static final String PROVIDER_INFO = "GMKai JSSE Provider Version 0.1";


    public GMKaiProvider() {

        super(PROVIDER_NAME, PROVIDER_VERSION, PROVIDER_INFO);
        put("SSLContext.TLCP", GMKaiSSLContextSpi.class.getName());
        put("KeyManagerFactory.TLCPX509", GMKaiTLCPX509KeyManagerFactory.class.getName());
        put("TrustManagerFactory.TLCPX509", GMKaiTLCPX509TrustManagerFactory.class.getName());
    }

}
