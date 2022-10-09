package net.gmkai;

import com.google.common.collect.ImmutableList;
import net.gmkai.crypto.impl.bc.BcTLSCrypto;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import test.TrustAllManager;

import java.io.IOException;
import java.net.InetAddress;
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

public class GMKaiServerSocketFactoryTest {

    GMKaiServerSocketFactory gmKaiServerSocketFactory;

    private GMKaiSSLParameters gmKaiSSLParameters;

    @BeforeEach
    public void setUp() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, NoSuchProviderException, IOException {

        ImmutableList<ProtocolVersion> protocolVersions = ImmutableList.of(ProtocolVersion.TLCP11);

        ImmutableList<TLSCipherSuite> cipherSuites = ImmutableList.of(ECC_SM4_CBC_SM3);

        gmKaiSSLParameters = new GMKaiSSLParameters(true,
                protocolVersions, cipherSuites, protocolVersions, cipherSuites, protocolVersions, cipherSuites);

        ContextData contextData = createTextContextData(gmKaiSSLParameters);

        gmKaiServerSocketFactory = new GMKaiServerSocketFactory(contextData);
    }


    @Test
    public void should_create_server_socket() throws IOException {

        assertThat(gmKaiServerSocketFactory.createServerSocket(25545), is(notNullValue()));
        assertThat(gmKaiServerSocketFactory.createServerSocket(25546, 3), is(notNullValue()));
        assertThat(gmKaiServerSocketFactory.createServerSocket(25547, 1, InetAddress.getLocalHost()), is(notNullValue()));
    }

    @Test
    public void should_get_cipher_suites() {

        assertThat(gmKaiServerSocketFactory.getSupportedCipherSuites(), is(gmKaiSSLParameters.getSupportedCipherSuites().stream().map(cs -> cs.name).toArray(String[]::new)));
        assertThat(gmKaiServerSocketFactory.getDefaultCipherSuites(), is(gmKaiSSLParameters.getEnableCipherSuites().stream().map(cs -> cs.name).toArray(String[]::new)));

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
