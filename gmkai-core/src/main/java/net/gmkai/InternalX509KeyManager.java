package net.gmkai;

import javax.net.ssl.KeyManager;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;


public interface InternalX509KeyManager extends KeyManager {

    String[] getClientAliases(String keyType, Principal[] issuers);

    String chooseClientAlias(String[] keyType, Principal[] issuers);

    String[] getServerAliases(String keyType, Principal[] issuers);

    String chooseServerAlias(String keyType, Principal[] issuers);

    X509Certificate[] getCertificateChain(String alias);

    PrivateKey getPrivateKey(String alias);
}
