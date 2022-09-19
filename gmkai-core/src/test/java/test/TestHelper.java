package test;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.zz.gmhelper.SM2Util;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
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

    public static byte[] rsaDecrypt(RSAPrivateKey rsaPrivateKey, byte[] encryptedText) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

        Cipher cipher = Cipher.getInstance("RSA/None/PKCS1Padding", BouncyCastleProvider.PROVIDER_NAME);
        cipher.init(Cipher.DECRYPT_MODE, rsaPrivateKey);

        return cipher.doFinal(encryptedText, 0, encryptedText.length);
    }

    public static byte[] rsaEncrypt(RSAPublicKey rsaPublicKey, byte[] text) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

        Cipher cipher = Cipher.getInstance("RSA/None/PKCS1Padding", BouncyCastleProvider.PROVIDER_NAME);
        cipher.init(Cipher.ENCRYPT_MODE, rsaPublicKey);

        return cipher.doFinal(text, 0, text.length);
    }

    public static byte[] sm2Decrypt(ECPrivateKey ecPrivateKey, byte[] encryptedText) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

        Cipher cipher = Cipher.getInstance("SM2", BouncyCastleProvider.PROVIDER_NAME);
        cipher.init(Cipher.DECRYPT_MODE, ecPrivateKey);

        return cipher.doFinal(encryptedText, 0, encryptedText.length);
    }

    public static byte[] sm2Encrypt(ECPublicKey ecPublicKey, byte[] text) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

        Cipher cipher = Cipher.getInstance("SM2", BouncyCastleProvider.PROVIDER_NAME);
        cipher.init(Cipher.ENCRYPT_MODE, ecPublicKey);
        return cipher.doFinal(text, 0, text.length);
    }

    public static byte[] sm2EncryptWithDer(ECPublicKey ecPublicKey, byte[] text) throws Exception {
        BCECPublicKey bcEcPublicKey = ECPublicKey2BCECPublicKey(ecPublicKey);

        return SM2Util.encodeSM2CipherToDER(SM2Util.encrypt(bcEcPublicKey, text));
    }

    public static byte[] sm2DecryptWithDer(ECPrivateKey ecPrivateKey, byte[] encryptedText) throws Exception {

        BCECPrivateKey bcecPrivateKey = ECPrivateKey2BCECPrivateKey(ecPrivateKey);

        return SM2Util.decrypt(bcecPrivateKey, SM2Util.decodeDERSM2Cipher(encryptedText));
    }


    static BCECPublicKey ECPublicKey2BCECPublicKey(ECPublicKey ecPublicKey) {
        if (ecPublicKey instanceof BCECPublicKey) {
            return (BCECPublicKey) ecPublicKey;
        }
        return new BCECPublicKey(ecPublicKey, BouncyCastleProvider.CONFIGURATION);
    }

    static BCECPrivateKey ECPrivateKey2BCECPrivateKey(ECPrivateKey ecPrivateKey) {
        if (ecPrivateKey instanceof BCECPrivateKey) {
            return (BCECPrivateKey) ecPrivateKey;
        }
        return new BCECPrivateKey(ecPrivateKey, BouncyCastleProvider.CONFIGURATION);
    }

    public static void main(String[] args) {

    }
}
