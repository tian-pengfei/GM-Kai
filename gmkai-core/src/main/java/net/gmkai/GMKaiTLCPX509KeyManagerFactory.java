package net.gmkai;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactorySpi;
import javax.net.ssl.ManagerFactoryParameters;
import java.security.*;
import java.util.Objects;

public class GMKaiTLCPX509KeyManagerFactory extends KeyManagerFactorySpi {

    private GMKaiTLCPX509KeyManager keyManager;

    @Override
    protected void engineInit(KeyStore ks, char[] password) {
        keyManager = new GMKaiTLCPX509KeyManager(ks, password);
    }

    @Override
    protected void engineInit(ManagerFactoryParameters spec) {
        throw new UnsupportedOperationException();
    }

    @Override
    protected KeyManager[] engineGetKeyManagers() {
        if (Objects.isNull(keyManager)) {
            throw new IllegalStateException("KeyManagerFactory not initialized");
        }

        return new KeyManager[]{keyManager};
    }
}
