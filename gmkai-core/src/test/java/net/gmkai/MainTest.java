package net.gmkai;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.net.ssl.*;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsStringIgnoringCase;
import static org.hamcrest.Matchers.equalTo;
import static test.TestHelper.*;

public class MainTest {

    static {
        Security.addProvider(new BouncyCastleProvider());
        Security.addProvider(new GMKaiProvider());
    }

    private SSLContext sslContext;

    private KeyManagerFactory keyManagerFactory;

    private TrustManagerFactory trustManagerFactory;

    private static final String remoteServerUrl = "https://ebssec.boc.cn";

    private static final String response = "Hello! this is GMKai!";


    @BeforeEach
    public void setUp() throws NoSuchAlgorithmException {
        sslContext = SSLContext.getInstance("TLCP");
        keyManagerFactory = KeyManagerFactory.getInstance("TLCPX509");
        trustManagerFactory = TrustManagerFactory.getInstance("TLCPX509");
    }

    @Test
    public void should_client_request() throws IOException, KeyManagementException, CertificateException, KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException {

        KeyStore keyStore = loadKeyStoreFromTrustedListPem("src/test/resources/trusted.certs.pem");

        trustManagerFactory.init(keyStore);

        sslContext.init(null, trustManagerFactory.getTrustManagers(), null);

        SSLSocketFactory ssf = sslContext.getSocketFactory();

        String result = sendHttpGetRequest(ssf, remoteServerUrl);

        assertThat(result, containsStringIgnoringCase("<html>"));
    }

    @Test
    public void should_server_handle_request() throws Exception {

        KeyStore keyStore = loadKeyStoreFromPFX("src/test/resources/sm2.gmkai.pfx", "12345678");

        keyManagerFactory.init(keyStore, "12345678".toCharArray());

        sslContext.init(keyManagerFactory.getKeyManagers(), null, new SecureRandom());

        SSLServerSocketFactory sslServerSocketFactory = sslContext.getServerSocketFactory();

        asyncExecute(() -> httpServerStart(8443, sslServerSocketFactory, response));

        String re = sendHttpGetRequestByTLCP1_1("https://localhost:8443/");
        assertThat(re, equalTo(response));
    }

    @Test
    public void should_client_request_server() throws Exception {


        KeyStore serverKeyStore = loadKeyStoreFromPFX("src/test/resources/sm2.gmkai.pfx", "12345678");

        KeyStore clientKeyStore = loadKeyStoreFromTrustedListPem("src/test/resources/trusted.certs.pem");

        keyManagerFactory.init(serverKeyStore, "12345678".toCharArray());

        trustManagerFactory.init(clientKeyStore);

        sslContext.init(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(), new SecureRandom());

        SSLServerSocketFactory sslServerSocketFactory = sslContext.getServerSocketFactory();

        asyncExecute(() -> httpServerStart(9443, sslServerSocketFactory, response));

        SSLSocketFactory ssf = sslContext.getSocketFactory();

        String re = sendHttpGetRequest(ssf, "https://localhost:9443/");

        assertThat(re, equalTo(response));
    }


}
