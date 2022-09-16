package test;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public class TestHelper {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static KeyStore getKeyStore(String pfxFilePath, String password) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, NoSuchProviderException {

        KeyStore pfx = KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME);

        pfx.load(new FileInputStream(pfxFilePath), password.toCharArray());

        return pfx;
    }

    public static PrivateKey decodePrivateKey(String filePath) throws IOException {
        try (PEMParser pemParser = new PEMParser(new FileReader(filePath))) {
            Object pem = pemParser.readObject();
            if (pem instanceof PrivateKeyInfo) {
                JcaPEMKeyConverter converter = new JcaPEMKeyConverter()
                        .setProvider(BouncyCastleProvider.PROVIDER_NAME);
                PrivateKeyInfo keyInfo = (PrivateKeyInfo) pem;
                return converter.getPrivateKey(keyInfo);
            }
            throw new RuntimeException("invalid key file.");
        }
    }

    public static PublicKey decodePublicKey(String filePath) throws IOException {
        try (PEMParser pemParser = new PEMParser(new FileReader(filePath))) {
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter()
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME);
            SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(pemParser.readObject());
            return converter.getPublicKey(publicKeyInfo);
        }
    }

    public static byte[] rsaDecrypt(RSAPrivateKey rsaPrivateKey, byte[] decryptText) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

        Cipher cipher = Cipher.getInstance("RSA/None/PKCS1Padding", BouncyCastleProvider.PROVIDER_NAME);
        cipher.init(Cipher.DECRYPT_MODE, rsaPrivateKey);

        return cipher.doFinal(decryptText, 0, decryptText.length);
    }

    public static byte[] rsaEncrypt(RSAPublicKey rsaPublicKey, byte[] text) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

        Cipher cipher = Cipher.getInstance("RSA/None/PKCS1Padding", BouncyCastleProvider.PROVIDER_NAME);
        cipher.init(Cipher.ENCRYPT_MODE, rsaPublicKey);

        return cipher.doFinal(text, 0, text.length);
    }
}
