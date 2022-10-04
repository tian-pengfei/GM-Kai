package net.gmkai;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedKeyManager;
import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;


public interface InternalX509KeyManager extends InternalKeyManager {

    String[] getClientAliases(String keyType, Principal[] issuers);

    String chooseClientAlias(String[] keyType, Principal[] issuers);

    String[] getServerAliases(String keyType, Principal[] issuers);

    String chooseServerAlias(String keyType, Principal[] issuers);

    X509Certificate[] getCertificateChain(String alias);

    PrivateKey getPrivateKey(String alias);


    static InternalX509KeyManager getInstance(X509ExtendedKeyManager x509ExtendedKeyManager, Socket socket) {

        return new InternalX509KeyManager() {
            @Override
            public String[] getClientAliases(String keyType, Principal[] issuers) {
                return x509ExtendedKeyManager.getClientAliases(keyType, issuers);
            }

            @Override
            public String chooseClientAlias(String[] keyType, Principal[] issuers) {
                return x509ExtendedKeyManager.chooseClientAlias(keyType, issuers, socket);
            }

            @Override
            public String[] getServerAliases(String keyType, Principal[] issuers) {
                return x509ExtendedKeyManager.getServerAliases(keyType, issuers);
            }

            @Override
            public String chooseServerAlias(String keyType, Principal[] issuers) {
                return x509ExtendedKeyManager.chooseServerAlias(keyType, issuers, socket);
            }

            @Override
            public X509Certificate[] getCertificateChain(String alias) {
                return x509ExtendedKeyManager.getCertificateChain(alias);
            }

            @Override
            public PrivateKey getPrivateKey(String alias) {
                return x509ExtendedKeyManager.getPrivateKey(alias);
            }
        };
    }

    static InternalX509KeyManager getInstance(X509ExtendedKeyManager x509ExtendedKeyManager, SSLEngine sslEngine) {

        return new InternalX509KeyManager() {
            @Override
            public String[] getClientAliases(String keyType, Principal[] issuers) {
                return x509ExtendedKeyManager.getClientAliases(keyType, issuers);
            }

            @Override
            public String chooseClientAlias(String[] keyType, Principal[] issuers) {
                return x509ExtendedKeyManager.chooseEngineClientAlias(keyType, issuers, sslEngine);
            }

            @Override
            public String[] getServerAliases(String keyType, Principal[] issuers) {
                return x509ExtendedKeyManager.getServerAliases(keyType, issuers);
            }

            @Override
            public String chooseServerAlias(String keyType, Principal[] issuers) {
                return x509ExtendedKeyManager.chooseEngineServerAlias(keyType, issuers, sslEngine);
            }

            @Override
            public X509Certificate[] getCertificateChain(String alias) {
                return x509ExtendedKeyManager.getCertificateChain(alias);
            }

            @Override
            public PrivateKey getPrivateKey(String alias) {
                return x509ExtendedKeyManager.getPrivateKey(alias);
            }
        };
    }
}
