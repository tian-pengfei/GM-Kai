package test;

import com.aliyun.gmsse.GMProvider;
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
import javax.net.ssl.*;
import java.io.*;
import java.net.Socket;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.stream.Collectors;

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

    public static void sendAsyncConnectTLCPServer(String url) {

        new Thread(() -> {
            try {
                GMProvider provider = new GMProvider();
                SSLContext sc = SSLContext.getInstance("TLS", provider);
                sc.init(null, new TrustManager[]{new TrustAllManager()}, null);
                SSLSocketFactory ssf = sc.getSocketFactory();

                URL serverUrl = new URL(url);
                HttpsURLConnection conn = (HttpsURLConnection) serverUrl.openConnection();
                conn.setRequestMethod("GET");
                // set SSLSocketFactory
                conn.setSSLSocketFactory(ssf);
                conn.connect();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }).start();
    }

    public static X509Certificate getX509CertificateFromPEM(String certPath) throws CertificateException, NoSuchProviderException, IOException {

        CertificateFactory cf = CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);

        try (FileInputStream is = new FileInputStream(certPath)) {
            return (X509Certificate) cf.generateCertificate(is);
        }
    }

    public static List<X509Certificate> getX509CertificatesFromPEM(String certPath) throws CertificateException, NoSuchProviderException, IOException {

        CertificateFactory cf = CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);

        try (FileInputStream is = new FileInputStream(certPath)) {
            return cf.generateCertificates(is).stream().
                    map(certificate -> (X509Certificate) certificate).
                    collect(Collectors.toList());
        }
    }

    public static String sendHttpGetRequest(SSLSocketFactory sslSocketFactory, String url) throws IOException {

        URL serverUrl = new URL(url);

        HttpsURLConnection conn = (HttpsURLConnection) serverUrl.openConnection();
        conn.setRequestMethod("GET");
        conn.setSSLSocketFactory(sslSocketFactory);
        conn.connect();
        return readFromStream(conn.getInputStream());
    }

    public static String sendHttpGetRequestByTLCP1_1(String url) throws IOException, KeyManagementException, NoSuchAlgorithmException {

        GMProvider provider = new GMProvider();
        SSLContext sc = SSLContext.getInstance("TLS", provider);
        sc.init(null, new TrustManager[]{new TrustAllManager()}, null);
        SSLSocketFactory ssf = sc.getSocketFactory();

        return sendHttpGetRequest(ssf, url);
    }

    public static String readFromStream(InputStream inputStream) throws IOException {
        InputStreamReader inputStreamReader = new InputStreamReader(inputStream, StandardCharsets.UTF_8);
        BufferedReader bufferedReader = new BufferedReader(inputStreamReader);
        String str;
        StringBuilder buffer = new StringBuilder();
        while ((str = bufferedReader.readLine()) != null) {
            buffer.append(str);
        }
        return buffer.toString();
    }


    public static KeyStore loadKeyStoreFromTrustedListPem(String filePath) throws KeyStoreException, CertificateException, NoSuchProviderException, IOException, NoSuchAlgorithmException {
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(null, null);
        List<X509Certificate> x509Certificates = TestHelper.getX509CertificatesFromPEM(filePath);

        for (X509Certificate cert : x509Certificates) {
            keyStore.setCertificateEntry(cert.getSerialNumber().toString(), cert);
        }
        return keyStore;
    }

    public static KeyStore loadKeyStoreFromPFX(String filePath, String psw) throws CertificateException, NoSuchAlgorithmException, KeyStoreException, NoSuchProviderException, IOException {
        return TestHelper.getKeyStore(filePath, psw);
    }

    public static void asyncExecute(Runnable runnable) {
        new Thread(() -> {
            try {
                runnable.run();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }).start();
    }


    public static void httpServerStart(int port, SSLServerSocketFactory sslServerSocketFactory, String response) throws IOException {

        SSLServerSocket serverSocket = (SSLServerSocket) sslServerSocketFactory.createServerSocket(port);

        while (true) {
            try (Socket socket = serverSocket.accept();
                 DataInputStream in = new DataInputStream(socket.getInputStream());
                 DataOutputStream out = new DataOutputStream(socket.getOutputStream());
            ) {


                byte[] buf = new byte[8192];
                int len = in.read(buf);
                if (len == -1) {
                    System.out.println("eof");
                }
                byte[] body = response.getBytes();
                byte[] resp = ("HTTP/1.1 200 OK\r\n" +
                        "Server: TLCP/1.1\r\n" +
                        "Content-Length:" + body.length + "\r\n" +
                        "Content-Type: text/plain\r\n" +
                        "Connection: close\r\n\r\n").getBytes();

                out.write(resp, 0, resp.length);
                out.write(body, 0, body.length);
                out.flush();
            }
        }
    }


    public interface Runnable {

        void run() throws Exception;
    }

}
