package com.tianpengfei.gmkai;

import javax.net.ssl.X509KeyManager;
import java.net.Socket;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Collections;

public class GMX509KeyManager implements X509KeyManager {

    private final KeyStore keyStore;

    private final char[] password;

    GMX509KeyManager(KeyStore keyStore, char[] password) {
        this.keyStore = keyStore;
        this.password = password;
    }


    @Override
    public String[] getClientAliases(String keyType, Principal[] issuers) {


        try {
            return Collections.list(keyStore.aliases()).toArray(new String[0]);
        } catch (KeyStoreException e) {
            throw new RuntimeException(e.getMessage());
        }
    }

    @Override
    public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {

        throw new UnsupportedOperationException();
    }

    @Override
    public String[] getServerAliases(String keyType, Principal[] issuers) {
        throw new UnsupportedOperationException();
    }

    @Override
    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
        throw new UnsupportedOperationException();
    }

    @Override
    public X509Certificate[] getCertificateChain(String alias) {

        try {
            return (X509Certificate[]) keyStore.getCertificateChain(alias).clone();
        } catch (KeyStoreException e) {
            return new X509Certificate[0];
        }
    }

    public X509Certificate[] getCertificateChain(String sig, String enc) {
        if (sig.equals(enc)) {
            return getCertificateChain(sig);
        }
        try {
            return new X509Certificate[]{(X509Certificate) keyStore.getCertificate(sig),
                    (X509Certificate) keyStore.getCertificate(enc)}.clone();
        } catch (KeyStoreException e) {
            return new X509Certificate[0];
        }

    }

    @Override
    public PrivateKey getPrivateKey(String alias) {
        try {
            Key key = keyStore.getKey(alias, password);
            if (key instanceof PrivateKey) {
                return (PrivateKey) key;
            }

        } catch (Exception ignored) {

        }
        return null;
    }
}
