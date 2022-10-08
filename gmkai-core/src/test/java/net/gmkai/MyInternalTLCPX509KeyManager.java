package net.gmkai;

import test.TestHelper;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class MyInternalTLCPX509KeyManager implements InternalTLCPX509KeyManager {

    KeyStore sm2KeyStore = TestHelper.getKeyStore("src/test/resources/sm2.gmkai.pfx", "12345678");

    public MyInternalTLCPX509KeyManager() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, NoSuchProviderException, IOException {
    }

    @Override
    public String[] getClientAliases(String keyType, Principal[] issuers) {
        return new String[0];
    }

    @Override
    public String[] getServerAliases(String keyType, Principal[] issuers) {
        return new String[0];
    }

    @Override
    public PrivateKey getPrivateKey(String alias) {
        try {
            return (PrivateKey) sm2KeyStore.getKey(alias, "12345678".toCharArray());
        } catch (Exception e) {
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    @Override
    public String chooseClientSigAlias(String[] keyType, Principal[] issuers) {
        return "sig";
    }

    @Override
    public String chooseClientEncAlias(String[] keyType, Principal[] issuers) {
        return "enc";
    }

    @Override
    public String chooseServerSigAlias(String keyType, Principal[] issuers) {
        return "sig";
    }

    @Override
    public String chooseServerEncAlias(String keyType, Principal[] issuers) {
        return "enc";
    }

    @Override
    public X509Certificate[] getCertificateChain(String sigAlias, String encAlias) {
        try {
            return new X509Certificate[]{(X509Certificate) sm2KeyStore.getCertificate(sigAlias), (X509Certificate) sm2KeyStore.getCertificate(encAlias)};
        } catch (Exception e) {
            throw new RuntimeException(e.getMessage(), e);
        }
    }
}
