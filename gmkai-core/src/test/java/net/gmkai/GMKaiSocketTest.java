package net.gmkai;

import com.google.common.collect.ImmutableList;
import net.gmkai.crypto.impl.bc.BcTLSCrypto;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import test.TrustAllManager;

import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLParameters;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;

import static net.gmkai.ProtocolVersion.TLCP11;
import static net.gmkai.TLSCipherSuite.ECC_SM4_CBC_SM3;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.*;

public class GMKaiSocketTest {

    private ContextData contextData;

    GMKaiSSLParameters gmKaiSSLParameters;

    GMKaiSocket gmKaiSocket;

    @BeforeEach
    public void setUp() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, NoSuchProviderException, IOException {
        ImmutableList<ProtocolVersion> protocolVersions = ImmutableList.of(TLCP11);

        ImmutableList<TLSCipherSuite> cipherSuites = ImmutableList.of(ECC_SM4_CBC_SM3);

        gmKaiSSLParameters = new GMKaiSSLParameters(true,
                protocolVersions, cipherSuites, protocolVersions, cipherSuites, protocolVersions, cipherSuites);

        this.contextData = createContextData(gmKaiSSLParameters);

        gmKaiSocket =
                new GMKaiSocket("ebssec.boc.cn", 443, contextData, gmKaiSSLParameters);
    }


    @Test
    public void should_start_handshake() throws IOException {
        gmKaiSocket.startHandshake();
    }

    @Test
    public void should_get_supported_cipher_suites() {
        assertThat(gmKaiSocket.getSupportedCipherSuites(),
                is(Matchers.equalTo(new String[]{ECC_SM4_CBC_SM3.name})));
    }

    @Test
    public void should_get_enable_cipher_suites() {
        assertThat(gmKaiSocket.getEnabledCipherSuites(),
                is(Matchers.equalTo(new String[]{ECC_SM4_CBC_SM3.name})));
    }

    @Test
    public void should_get_enable_protocols() {
        assertThat(gmKaiSocket.getEnabledProtocols(),
                is(Matchers.equalTo(new String[]{TLCP11.name})));
    }

    @Test
    public void should_get_handshake_session_before_start_handshake() throws IOException {

        assertThat(gmKaiSocket.getHandshakeSession(), is(nullValue()));

    }


    @Test
    public void should_get_handshake_session_after_start_handshake() throws IOException {
        gmKaiSocket.startHandshake();

        assertThat(gmKaiSocket.getHandshakeSession(), is(notNullValue()));

    }

    @Test
    public void should_get_session_after_start_handshake() {

        assertThat(gmKaiSocket.getSession(), is(notNullValue()));

    }

    @Test
    public void should_get_enable_session_creation() {

        assertThat(gmKaiSocket.getEnableSessionCreation(), is(gmKaiSSLParameters.getEnableSessionCreation()));

    }

    @Test
    public void should_set_enable_session_creation() {
        gmKaiSocket.setEnableSessionCreation(true);
        assertThat(gmKaiSocket.getEnableSessionCreation(), is(true));

    }

    @Test
    public void should_get_stream() throws IOException {

        assertThat(gmKaiSocket.getInputStream(), is(notNullValue()));
        assertThat(gmKaiSocket.getOutputStream(), is(notNullValue()));

    }

    @Test
    public void should_set_want_client_auth() {

        gmKaiSocket.setWantClientAuth(true);
        assertThat(gmKaiSocket.getWantClientAuth(), is(true));
        assertThat(gmKaiSocket.getNeedClientAuth(), is(false));
    }

    @Test
    public void should_set_need_client_auth() {

        gmKaiSocket.setNeedClientAuth(true);
        assertThat(gmKaiSocket.getWantClientAuth(), is(false));
        assertThat(gmKaiSocket.getNeedClientAuth(), is(true));
    }

    @Test
    public void should_get_client_auth() {

        assertThat(gmKaiSocket.getNeedClientAuth(), is(gmKaiSSLParameters.getNeedClientAuth()));
        assertThat(gmKaiSocket.getWantClientAuth(), is(gmKaiSSLParameters.getWantClientAuth()));
    }

    @Test
    public void should_get_client_mode() {

        assertThat(gmKaiSocket.getUseClientMode(), is(gmKaiSSLParameters.getUseClientMode()));
    }

    @Test
    public void should_set_client_mode() {
        gmKaiSocket.setUseClientMode(!gmKaiSSLParameters.getUseClientMode());
        assertThat(gmKaiSocket.getUseClientMode(), is(!gmKaiSSLParameters.getUseClientMode()));
    }

    @Test
    public void should_add_handshake_completed_listener() throws IOException {

        HandshakeCompletedListener handshakeCompletedListener = mock(HandshakeCompletedListener.class);

        gmKaiSocket.addHandshakeCompletedListener(handshakeCompletedListener);
        gmKaiSocket.startHandshake();
        verify(handshakeCompletedListener).handshakeCompleted(any());
    }

    @Test
    public void should_remove_handshake_completed_listener() throws IOException {

        HandshakeCompletedListener handshakeCompletedListener = mock(HandshakeCompletedListener.class);

        gmKaiSocket.addHandshakeCompletedListener(handshakeCompletedListener);
        gmKaiSocket.removeHandshakeCompletedListener(handshakeCompletedListener);
        gmKaiSocket.startHandshake();
        verifyNoMoreInteractions(handshakeCompletedListener);
    }

    @Test
    public void should_set_parameters() {
        SSLParameters sslParameters = new SSLParameters();
        sslParameters.setNeedClientAuth(true);

        assertThat(gmKaiSocket.getNeedClientAuth(), is(false));
        gmKaiSocket.setSSLParameters(sslParameters);
        assertThat(gmKaiSocket.getNeedClientAuth(), is(true));
    }

    @Test
    public void should_create_socket() throws IOException {
        //todo
    }


    private ContextData createContextData(GMKaiSSLParameters gmKaiSSLParameters) throws CertificateException, NoSuchAlgorithmException, KeyStoreException, NoSuchProviderException, IOException {

        return new ContextData(new GMKaiSSLSessionContext(),
                new GMKaiSSLSessionContext(),
                new MyTLCPX509KeyManager(), new TrustAllManager(), new SecureRandom(), new BcTLSCrypto()
                , gmKaiSSLParameters, gmKaiSSLParameters);
    }
}
