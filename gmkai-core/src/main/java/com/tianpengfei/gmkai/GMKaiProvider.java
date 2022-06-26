package com.tianpengfei.gmkai;

import java.security.Provider;

public class GMKaiProvider extends Provider {

    GMKaiProvider() {
        super(PROVIDER_NAME, 1.0, "Tian Peng Fei's GMProvider");
//        put("SSLContext.GMSSL");
//        put();
//        put();
    }


    public static final String PROVIDER_NAME = "GMKaiProvider";
}
