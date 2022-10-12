package net.gmkai;

import javax.net.ssl.SSLEngine;
import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public class DummyTLCPX509KeyManager implements TLCPX509KeyManager {
    @Override
    public String[] getClientAliases(String keyType, Principal[] issuers) {
        return new String[0];
    }

    @Override
    public String[] getServerAliases(String keyType, Principal[] issuers) {
        return new String[0];
    }

    @Override
    public X509Certificate[] getCertificateChain(String sigAlias, String encAlias) {
        return new X509Certificate[0];
    }

    @Override
    public PrivateKey getPrivateKey(String alias) {
        return null;
    }

    @Override
    public String chooseClientSigAlias(String[] keyType, Principal[] issuers, Socket socket) {
        return null;
    }

    @Override
    public String chooseClientEncAlias(String[] keyType, Principal[] issuers, Socket socket) {
        return null;
    }

    @Override
    public String chooseServerSigAlias(String keyType, Principal[] issuers, Socket socket) {
        return null;
    }

    @Override
    public String chooseServerEncAlias(String keyType, Principal[] issuers, Socket socket) {
        return null;
    }

    @Override
    public String chooseEngineClientSigAlias(String[] keyType, Principal[] issuers, SSLEngine engine) {
        return null;
    }

    @Override
    public String chooseEngineClientEncAlias(String[] keyType, Principal[] issuers, SSLEngine engine) {
        return null;
    }

    @Override
    public String chooseEngineServerSigAlias(String keyType, Principal[] issuers, SSLEngine engine) {
        return null;
    }

    @Override
    public String chooseEngineServerEncAlias(String keyType, Principal[] issuers, SSLEngine engine) {
        return null;
    }
}
