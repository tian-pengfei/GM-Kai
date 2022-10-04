package net.gmkai;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLEngine;
import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public interface TLCPX509KeyManager extends KeyManager {

    String[] getClientAliases(String keyType, Principal[] issuers);

    String[] getServerAliases(String keyType, Principal[] issuers);

    X509Certificate[] getCertificateChain(String sigAlias, String encAlias);

    PrivateKey getPrivateKey(String alias);

    String chooseClientSigAlias(String[] keyType, Principal[] issuers,
                                Socket socket);

    String chooseClientEncAlias(String[] keyType, Principal[] issuers,
                                Socket socket);

    String chooseServerSigAlias(String keyType, Principal[] issuers,
                                Socket socket);

    String chooseServerEncAlias(String keyType, Principal[] issuers,
                                Socket socket);

    String chooseEngineClientSigAlias(String[] keyType,
                                      Principal[] issuers, SSLEngine engine);

    String chooseEngineClientEncAlias(String[] keyType,
                                      Principal[] issuers, SSLEngine engine);

    String chooseEngineServerSigAlias(String keyType,
                                      Principal[] issuers, SSLEngine engine);

    String chooseEngineServerEncAlias(String keyType,
                                      Principal[] issuers, SSLEngine engine);

}
