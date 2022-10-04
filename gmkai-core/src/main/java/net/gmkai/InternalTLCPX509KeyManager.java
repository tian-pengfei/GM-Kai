package net.gmkai;

import javax.net.ssl.SSLEngine;
import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public interface InternalTLCPX509KeyManager extends InternalKeyManager {

    String[] getClientAliases(String keyType, Principal[] issuers);

    String[] getServerAliases(String keyType, Principal[] issuers);

    PrivateKey getPrivateKey(String alias);

    String chooseClientSigAlias(String[] keyType, Principal[] issuers);

    String chooseClientEncAlias(String[] keyType, Principal[] issuers);

    String chooseServerSigAlias(String keyType, Principal[] issuers);

    String chooseServerEncAlias(String keyType, Principal[] issuers);

    X509Certificate[] getCertificateChain(String sigAlias, String encAlias);

    static InternalTLCPX509KeyManager getInstance(TLCPX509KeyManager tlcpx509KeyManager,
                                                  Socket socket) {

        return new InternalTLCPX509KeyManager() {
            @Override
            public String[] getClientAliases(String keyType, Principal[] issuers) {
                return tlcpx509KeyManager.getClientAliases(keyType, issuers);
            }

            @Override
            public String[] getServerAliases(String keyType, Principal[] issuers) {
                return tlcpx509KeyManager.getServerAliases(keyType, issuers);
            }

            @Override
            public PrivateKey getPrivateKey(String alias) {
                return tlcpx509KeyManager.getPrivateKey(alias);
            }

            @Override
            public String chooseClientSigAlias(String[] keyType, Principal[] issuers) {
                return tlcpx509KeyManager.chooseClientSigAlias(keyType, issuers, socket);
            }

            @Override
            public String chooseClientEncAlias(String[] keyType, Principal[] issuers) {
                return tlcpx509KeyManager.chooseClientEncAlias(keyType, issuers, socket);
            }

            @Override
            public String chooseServerSigAlias(String keyType, Principal[] issuers) {
                return tlcpx509KeyManager.chooseServerSigAlias(keyType, issuers, socket);
            }

            @Override
            public String chooseServerEncAlias(String keyType, Principal[] issuers) {
                return tlcpx509KeyManager.chooseServerEncAlias(keyType, issuers, socket);
            }

            @Override
            public X509Certificate[] getCertificateChain(String sigAlias, String encAlias) {
                return tlcpx509KeyManager.getCertificateChain(sigAlias, encAlias);
            }
        };
    }

    static InternalTLCPX509KeyManager getInstance(TLCPX509KeyManager tlcpx509KeyManager,
                                                  SSLEngine sslEngine) {

        return new InternalTLCPX509KeyManager() {
            @Override
            public String[] getClientAliases(String keyType, Principal[] issuers) {
                return tlcpx509KeyManager.getClientAliases(keyType, issuers);
            }

            @Override
            public String[] getServerAliases(String keyType, Principal[] issuers) {
                return tlcpx509KeyManager.getServerAliases(keyType, issuers);
            }

            @Override
            public PrivateKey getPrivateKey(String alias) {
                return tlcpx509KeyManager.getPrivateKey(alias);
            }

            @Override
            public String chooseClientSigAlias(String[] keyType, Principal[] issuers) {
                return tlcpx509KeyManager.chooseEngineClientSigAlias(keyType, issuers, sslEngine);
            }

            @Override
            public String chooseClientEncAlias(String[] keyType, Principal[] issuers) {
                return tlcpx509KeyManager.chooseEngineClientEncAlias(keyType, issuers, sslEngine);
            }

            @Override
            public String chooseServerSigAlias(String keyType, Principal[] issuers) {
                return tlcpx509KeyManager.chooseEngineServerSigAlias(keyType, issuers, sslEngine);
            }

            @Override
            public String chooseServerEncAlias(String keyType, Principal[] issuers) {
                return tlcpx509KeyManager.chooseEngineServerEncAlias(keyType, issuers, sslEngine);
            }

            @Override
            public X509Certificate[] getCertificateChain(String sigAlias, String encAlias) {
                return tlcpx509KeyManager.getCertificateChain(sigAlias, encAlias);
            }
        };
    }
}
