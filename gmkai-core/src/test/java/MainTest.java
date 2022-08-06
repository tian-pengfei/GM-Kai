import com.tianpengfei.gmkai.GMKaiProvider;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.Test;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class MainTest {

    static {
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
    }

    @Test
    public void test() throws IOException, NoSuchAlgorithmException, KeyManagementException, CertificateException, KeyStoreException {


        GMKaiProvider provider = new GMKaiProvider();

        KeyStore trustKeyStore = KeyStore.getInstance("JKS");
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        InputStream is = this.getClass().getClassLoader().getResourceAsStream("cert");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(is);
        trustKeyStore.load(null, null);
        trustKeyStore.setCertificateEntry("gmca", cert);
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("GMKaiX509", provider);
        tmf.init(trustKeyStore);


        SSLContext sc = SSLContext.getInstance("TLCP", provider);
        sc.init(null, tmf.getTrustManagers(), null);
        SSLSocketFactory ssf = sc.getSocketFactory();

//        URL serverUrl = new URL("https://ebssec.boc.cn");

        URL serverUrl = new URL("https://sm2test.ovssl.cn/");
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
        System.out.println(buffer.toString());
        Assert.assertEquals(200, conn.getResponseCode());
        Assert.assertEquals("ECC_SM4_CBC_SM3", conn.getCipherSuite());

    }


}
