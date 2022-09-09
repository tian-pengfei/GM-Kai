package net.gmkai;

import javax.net.ssl.KeyManager;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public interface InternalTLCPX509KeyManager extends KeyManager {

    String[] getClientAliases(String keyType, Principal[] issuers);

    String[] getServerAliases(String keyType, Principal[] issuers);

    PrivateKey getPrivateKey(String alias);

    String chooseClientSigAlias(String[] keyType, Principal[] issuers);

    String chooseClientEncAlias(String[] keyType, Principal[] issuers);

    String chooseServerSigAlias(String keyType, Principal[] issuers);

    String chooseServerEncAlias(String keyType, Principal[] issuers);

    X509Certificate[] getCertificateChain(String sigAlias, String encAlias);
}
