import com.tianpengfei.gmkai.GMKaiProvider;
import com.tianpengfei.gmkai.GMX509TrustManager;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import javax.net.ServerSocketFactory;
import javax.net.ssl.*;
import java.io.*;
import java.net.Socket;
import java.net.URL;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class MainTest {

    static {
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
        Security.insertProviderAt(new GMKaiProvider(), 2);
    }

    @Test
    public void clientTest() throws IOException, NoSuchAlgorithmException, KeyManagementException, CertificateException, KeyStoreException {


        KeyStore trustKeyStore = KeyStore.getInstance("JKS");
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        InputStream is = this.getClass().getClassLoader().getResourceAsStream("cert");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(is);
        trustKeyStore.load(null, null);
        trustKeyStore.setCertificateEntry("gmca", cert);
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("GMKaiX509");
        tmf.init(trustKeyStore);


        SSLContext sc = SSLContext.getInstance("TLCP");
        sc.init(null, tmf.getTrustManagers(), null);
        SSLSocketFactory ssf = sc.getSocketFactory();

//        URL serverUrl = new URL("https://ebssec.boc.cn");

        URL serverUrl = new URL("https://localhost:8443/");
//         serverUrl = new URL("https://localhost:8444/");

        HttpsURLConnection conn = (HttpsURLConnection) serverUrl.openConnection();
        conn.setRequestMethod("GET");
        // set SSLSocketFactory
        conn.setSSLSocketFactory(ssf);
        conn.connect();
        InputStream inputStream = conn.getInputStream();
        InputStreamReader inputStreamReader = new InputStreamReader(inputStream, "utf-8");
        BufferedReader bufferedReader = new BufferedReader(inputStreamReader);
        String str = null;
        StringBuffer buffer = new StringBuffer();
        while ((str = bufferedReader.readLine()) != null) {
            buffer.append(str);
        }
        Assert.assertEquals("this is a gm server", buffer.toString());
        Assert.assertEquals(200, conn.getResponseCode());
        Assert.assertEquals("ECC_SM4_CBC_SM3", conn.getCipherSuite());

    }

    @Before
    public void asyncServerStart() {
        new Thread(() -> {
            try {
                serverStart();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }).start();
    }

    public void serverStart() throws Exception {

        ServerSocketFactory fact = null;
        SSLServerSocket serversocket = null;


        int port = 8443;

        String pfxfile = "keystore/sm2.gmkai.pfx";
        String pwdpwd = "12345678";

        KeyStore pfx = KeyStore.getInstance("PKCS12");

        pfx.load(new FileInputStream(pfxfile), pwdpwd.toCharArray());

        fact = createServerSocketFactory(pfx, pwdpwd.toCharArray());
        serversocket = (SSLServerSocket) fact.createServerSocket(port);

        while (true) {
            Socket socket = null;
            try {
                socket = serversocket.accept();

                DataInputStream in = new DataInputStream(socket.getInputStream());
                DataOutputStream out = new DataOutputStream(socket.getOutputStream());

                byte[] buf = new byte[8192];
                int len = in.read(buf);
                if (len == -1) {
                    System.out.println("eof");
                }
                byte[] body = "this is a gm server".getBytes();
                byte[] resp = ("HTTP/1.1 200 OK\r\nServer: TLCP/1.1\r\nContent-Length:" + body.length + "\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n").getBytes();
                out.write(resp, 0, resp.length);
                out.write(body, 0, body.length);
                out.flush();
            } catch (Exception e) {
                e.printStackTrace();
            } finally {
                try {
                    socket.close();
                } catch (Exception e) {
                }
            }
        }
    }

    public static SSLServerSocketFactory createServerSocketFactory(KeyStore kepair, char[] pwd) throws Exception {
        TrustManager[] trust = {new GMX509TrustManager()};

        KeyManager[] kms = null;
        if (kepair != null) {
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("GMKaiX509");
            kmf.init(kepair, pwd);
            kms = kmf.getKeyManagers();
        }

        SSLContext ctx = SSLContext.getInstance("TLCP", "GMKai");
        SecureRandom secureRandom = new SecureRandom();
        ctx.init(kms, trust, secureRandom);

        ctx.getServerSessionContext().setSessionCacheSize(8192);
        ctx.getServerSessionContext().setSessionTimeout(3600);

        SSLServerSocketFactory factory = ctx.getServerSocketFactory();
        return factory;
    }


}
