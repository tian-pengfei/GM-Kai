package test;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

public class TestHelper {


    public static KeyStore getKeyStore(String pfxFilePath,String pwd) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {

        KeyStore pfx = KeyStore.getInstance("PKCS12",new BouncyCastleProvider());

        pfx.load(new FileInputStream(pfxFilePath), pwd.toCharArray());

        return pfx;
    }

}
