package com.tianpengfei.gmkai;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactorySpi;
import javax.net.ssl.ManagerFactoryParameters;
import java.security.*;

public class GMX509KeyManagerFactory extends KeyManagerFactorySpi {
    
    @Override
    protected void engineInit(KeyStore ks, char[] password) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {

    }

    @Override
    protected void engineInit(ManagerFactoryParameters spec) throws InvalidAlgorithmParameterException {

    }

    @Override
    protected KeyManager[] engineGetKeyManagers() {
        return new KeyManager[0];
    }
}
