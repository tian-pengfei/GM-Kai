package com.tianpengfei.gmkai;

import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactorySpi;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;

public class GMX509TrustManagerFactory extends TrustManagerFactorySpi {

    @Override
    protected void engineInit(KeyStore ks) throws KeyStoreException {

    }

    @Override
    protected void engineInit(ManagerFactoryParameters spec) throws InvalidAlgorithmParameterException {

    }

    @Override
    protected TrustManager[] engineGetTrustManagers() {
        return new TrustManager[0];
    }
}
