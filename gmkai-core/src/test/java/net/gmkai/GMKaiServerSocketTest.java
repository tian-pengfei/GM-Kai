package net.gmkai;

import com.google.common.collect.ImmutableList;
import net.gmkai.crypto.impl.bc.BcTLSCrypto;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import test.TrustAllManager;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;

import static net.gmkai.TLSCipherSuite.ECC_SM4_CBC_SM3;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class GMKaiServerSocketTest {

    private GMKaiServerSocket gmKaiServerSocket;
    private GMKaiSSLParameters gmKaiSSLParameters;
    private ContextData contextData;

    @BeforeEach
    public void setup() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, NoSuchProviderException, IOException {

        ImmutableList<ProtocolVersion> protocolVersions = ImmutableList.of(ProtocolVersion.TLCP11);

        ImmutableList<TLSCipherSuite> cipherSuites = ImmutableList.of(ECC_SM4_CBC_SM3);

        gmKaiSSLParameters = new GMKaiSSLParameters(true,
                protocolVersions, cipherSuites, protocolVersions, cipherSuites, protocolVersions, cipherSuites);
        contextData = createTextContextData(gmKaiSSLParameters);

        gmKaiServerSocket = new GMKaiServerSocket(contextData, gmKaiSSLParameters);
    }

    @Test
    public void should_create() throws IOException {
        new GMKaiServerSocket(contextData, gmKaiSSLParameters);
        new GMKaiServerSocket(25545, 3, contextData, gmKaiSSLParameters);
        new GMKaiServerSocket(25546, 1, InetAddress.getLocalHost(), contextData, gmKaiSSLParameters);
    }

    @Test
    public void should_accept() throws IOException {

        GMKaiServerSocket serverSocket = new GMKaiServerSocket(25545, 3, contextData, gmKaiSSLParameters);
        new Thread(() -> {
            try {
                new Socket("localhost", 25545);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }).start();

        Socket socket = serverSocket.accept();
        assertThat(socket, is(notNullValue()));

    }


    private static ContextData createTextContextData(GMKaiSSLParameters gmKaiSSLParameters) throws CertificateException, NoSuchAlgorithmException, KeyStoreException, NoSuchProviderException, IOException {

        ContextData contextData = mock(ContextData.class);
        when(contextData.getSecureRandom()).thenReturn(new SecureRandom());
        when(contextData.getTLSCrypto()).thenReturn(new BcTLSCrypto());
        when(contextData.getKeyManager()).thenReturn(new MyTLCPX509KeyManager());
        when(contextData.getX509TrustManager()).thenReturn(new TrustAllManager());
        when(contextData.getDefaultClientSSLParameters()).thenReturn(gmKaiSSLParameters);
        when(contextData.getDefaultServerSSLParameters()).thenReturn(gmKaiSSLParameters);
        when(contextData.getServerSSLSessionConText()).thenReturn(new GMKaiSSLSessionContext());
        when(contextData.getClientSSLSessionConText()).thenReturn(new GMKaiSSLSessionContext());
        return contextData;
    }
}
