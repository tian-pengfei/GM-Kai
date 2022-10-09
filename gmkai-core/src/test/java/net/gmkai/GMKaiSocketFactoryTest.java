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

public class GMKaiSocketFactoryTest {


    GMKaiSocketFactory gmKaiSocketFactory;

    GMKaiSSLParameters gmKaiSSLParameters;

    @BeforeEach
    public void setUp() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, NoSuchProviderException, IOException {
        ImmutableList<ProtocolVersion> protocolVersions = ImmutableList.of(ProtocolVersion.TLCP11);

        ImmutableList<TLSCipherSuite> cipherSuites = ImmutableList.of(ECC_SM4_CBC_SM3);

        gmKaiSSLParameters = new GMKaiSSLParameters(true,
                protocolVersions, cipherSuites, protocolVersions, cipherSuites, protocolVersions, cipherSuites);

        ContextData contextData = createTextContextData(gmKaiSSLParameters);
        gmKaiSocketFactory = new GMKaiSocketFactory(contextData);

    }

    @Test
    public void should_get_cipher_suite() {

        assertThat(gmKaiSocketFactory.getSupportedCipherSuites(),
                is(gmKaiSSLParameters.getSupportedCipherSuites().stream().map(cs -> cs.name).toArray(String[]::new)));

        assertThat(gmKaiSocketFactory.getDefaultCipherSuites(),
                is(gmKaiSSLParameters.getEnableCipherSuites().stream().map(cs -> cs.name).toArray(String[]::new)));

    }

    @Test
    public void should_create() throws IOException {

        assertThat(gmKaiSocketFactory.createSocket("ebssec.boc.cn", 443),
                is(notNullValue()));

        assertThat(gmKaiSocketFactory.createSocket("ebssec.boc.cn", 443, InetAddress.getLocalHost(), 5444),
                is(notNullValue()));

        assertThat(gmKaiSocketFactory.createSocket(InetAddress.getByName("ebssec.boc.cn"), 443),
                is(notNullValue()));

        assertThat(gmKaiSocketFactory.createSocket(InetAddress.getByName("ebssec.boc.cn"), 443, InetAddress.getLocalHost(), 1111),
                is(notNullValue()));


        Socket socket = new Socket("ebssec.boc.cn", 443);

        assertThat(gmKaiSocketFactory.createSocket(socket, "ebssec.boc.cn", 443, false),
                is(notNullValue()));

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
