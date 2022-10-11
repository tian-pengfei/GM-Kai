package net.gmkai;

import javax.net.ssl.SSLEngine;
import java.net.Socket;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Objects;
import java.util.function.Predicate;

//simple implementation
//todo: complete
public class GMKaiTLCPX509KeyManager implements TLCPX509KeyManager {

    private final KeyStore keyStore;

    private final char[] password;

    public GMKaiTLCPX509KeyManager(KeyStore keyStore, char[] password) {

        this.keyStore = keyStore;
        this.password = password;
    }

    @Override
    public String[] getClientAliases(String keyType, Principal[] issuers) {
        return getAlias(keyType, issuers);
    }

    @Override
    public String[] getServerAliases(String keyType, Principal[] issuers) {
        return getAlias(keyType, issuers);
    }

    @Override
    public X509Certificate[] getCertificateChain(String sigAlias, String encAlias) {
        try {
            X509Certificate sigCert = Objects.requireNonNull(
                    (X509Certificate) keyStore.getCertificate(sigAlias));

            X509Certificate encCert = Objects.requireNonNull(
                    (X509Certificate) keyStore.getCertificate(encAlias));

            return new X509Certificate[]{sigCert, encCert};

        } catch (Exception e) {
            return null;
        }
    }

    @Override
    public PrivateKey getPrivateKey(String alias) {
        try {
            return (PrivateKey) keyStore.getKey(alias, password);
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
            return null;
        }
    }

    @Override
    public String chooseClientSigAlias(String[] keyTypes, Principal[] issuers, Socket socket) {
        KeyUsage keyUsage = KeyUsage.digitalSignature;
        return chooseAlias(keyUsage, keyTypes, issuers);
    }

    @Override
    public String chooseClientEncAlias(String[] keyTypes, Principal[] issuers, Socket socket) {
        return chooseAlias(KeyUsage.keyAgreement, keyTypes, issuers);
    }

    @Override
    public String chooseServerSigAlias(String keyType, Principal[] issuers, Socket socket) {
        return chooseAlias(KeyUsage.digitalSignature, new String[]{keyType}, issuers);
    }

    @Override
    public String chooseServerEncAlias(String keyType, Principal[] issuers, Socket socket) {
        return chooseAlias(KeyUsage.keyAgreement,
                new String[]{keyType}, issuers);
    }

    @Override
    public String chooseEngineClientSigAlias(String[] keyTypes, Principal[] issuers, SSLEngine engine) {
        return chooseAlias(KeyUsage.digitalSignature, keyTypes, issuers);
    }

    @Override
    public String chooseEngineClientEncAlias(String[] keyTypes, Principal[] issuers, SSLEngine engine) {
        return chooseAlias(KeyUsage.keyAgreement,
                keyTypes, issuers);
    }

    @Override
    public String chooseEngineServerSigAlias(String keyType, Principal[] issuers, SSLEngine engine) {
        return chooseAlias(KeyUsage.digitalSignature,
                new String[]{keyType}, issuers);
    }

    @Override
    public String chooseEngineServerEncAlias(String keyType, Principal[] issuers, SSLEngine engine) {
        return chooseAlias(KeyUsage.keyAgreement,
                new String[]{keyType}, issuers);
    }

    private X509Certificate getX509Certificate(String alias) {
        try {
            return (X509Certificate) keyStore.getCertificate(alias);
        } catch (KeyStoreException e) {
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    private PublicKey getPublicKey(X509Certificate x509Certificate) {
        return x509Certificate.getPublicKey();
    }

    private Principal getPrincipal(X509Certificate x509Certificate) {
        return x509Certificate.getIssuerDN();
    }


    private String getPublicKeyAlgorithm(X509Certificate x509Certificate) {

        return getPublicKey(x509Certificate).getAlgorithm();
    }

    private boolean isKeyEntry(String alias) {
        try {
            return keyStore.isKeyEntry(alias);
        } catch (KeyStoreException e) {
            return false;
        }
    }

    private String getCertificateAlias(X509Certificate x509Certificate) {
        try {
            return keyStore.getCertificateAlias(x509Certificate);
        } catch (KeyStoreException e) {
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    private String chooseAlias(KeyUsage keyUsage, String[] keyTypes, Principal[] issuers) {
        try {
            X509Certificate x509Certificate = Collections.list(keyStore.aliases()).stream().
                    filter(this::isKeyEntry).
                    map(this::getX509Certificate).
                    filter(createFilter(issuers)).
                    filter(createFilter(keyTypes)).
                    filter(createFilter(keyUsage)).
                    findFirst().
                    orElseThrow(() -> new RuntimeException("cant find any suitable certifications "));
            return keyStore.getCertificateAlias(x509Certificate);
        } catch (KeyStoreException e) {
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    private String[] getAlias(String keyType, Principal[] issuers) {

        try {
            return Collections.list(keyStore.aliases()).stream().
                    filter(this::isKeyEntry).
                    map(this::getX509Certificate).
                    filter(createFilter(issuers)).
                    filter(createFilter(new String[]{keyType == null ? "NULL" : keyType})).
                    map(this::getCertificateAlias).toArray(String[]::new);
        } catch (KeyStoreException e) {
            throw new RuntimeException(e.getMessage(), e);
        }
    }


    private Predicate<X509Certificate> createFilter(Principal[] issuers) {
        if (issuers == null || issuers.length == 0) {
            return cert -> true;
        }

        return cert -> {
            for (Principal principal : issuers) {
                if (principal.equals(getPrincipal(cert))) {
                    return true;
                }
            }
            return false;
        };
    }

    private Predicate<X509Certificate> createFilter(String[] keyTypes) {
        if (keyTypes == null || keyTypes.length == 0) {
            return cert -> true;
        }
        return cert -> {
            String keyType = getPublicKeyAlgorithm(cert);
            for (String _keyType : keyTypes) {
                if (_keyType.equalsIgnoreCase("NULL") ||
                        _keyType.equalsIgnoreCase("UNKNOWN") || _keyType.equalsIgnoreCase(keyType)) {
                    return true;
                }
            }
            return false;
        };
    }

    private Predicate<X509Certificate> createFilter(KeyUsage keyUsage) {

        return x509Certificate -> new KeyUsage(x509Certificate).verify(keyUsage);
    }


}
