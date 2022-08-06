package com.tianpengfei.gmkai;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactorySpi;
import javax.net.ssl.ManagerFactoryParameters;
import java.security.*;

public class GMX509KeyManagerFactory extends KeyManagerFactorySpi {

    private GMX509KeyManager keyManager;


    @Override
    protected void engineInit(KeyStore ks, char[] password) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
        keyManager = new GMX509KeyManager(ks, password);
    }

    @Override
    protected void engineInit(ManagerFactoryParameters spec) throws InvalidAlgorithmParameterException {
        throw new UnsupportedOperationException();
    }

    @Override
    protected KeyManager[] engineGetKeyManagers() {
        return new KeyManager[]{keyManager};
    }
}
