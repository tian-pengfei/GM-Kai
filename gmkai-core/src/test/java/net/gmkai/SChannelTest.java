package net.gmkai;

import com.google.common.collect.ImmutableList;
import net.gmkai.crypto.impl.bc.BcTLSCrypto;
import net.gmkai.event.GMKaiEventBus;
import net.gmkai.event.TLSEventBus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import test.TestHelper;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import static net.gmkai.TLSCipherSuite.ECC_SM4_CBC_SM3;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class SChannelTest {


    TLSEventBus tlsEventBus;
    InternalContextData internalContextData;
    GMKaiSSLParameters gmKaiSSLParameters;

    @BeforeEach
    public void setUp() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, NoSuchProviderException, IOException {

        tlsEventBus = new GMKaiEventBus();

        ImmutableList<ProtocolVersion> protocolVersions = ImmutableList.of(ProtocolVersion.TLCP11);

        ImmutableList<TLSCipherSuite> cipherSuites = ImmutableList.of(ECC_SM4_CBC_SM3);

        gmKaiSSLParameters = new GMKaiSSLParameters(true,
                protocolVersions, cipherSuites, protocolVersions, cipherSuites, protocolVersions, cipherSuites);
        internalContextData = createTextInternalContextData();

    }


    @Test
    public void should_tlcp11_client_handshake_with_ecc_sm4_cbc_sm3() throws IOException {

        String addr = "ebssec.boc.cn";
        int port = 443;
        Socket socket = new Socket();
        socket.connect(new InetSocketAddress(addr, port), 2000);
        PeerInfoProvider peerInfoProvider = new PeerInfoProvider() {
            @Override
            public String getHostname() {
                return addr;
            }

            @Override
            public int getPort() {
                return port;
            }
        };


        SChannel sChannel = new SChannel(
                tlsEventBus,
                internalContextData,
                gmKaiSSLParameters, peerInfoProvider, socket.getInputStream(), socket.getOutputStream());

        sChannel.startHandshake();
        assertThat(sChannel.getHandshakeSession().getCipherSuite(),
                is(ECC_SM4_CBC_SM3.name));
    }

    @Test
    public void should_tlcp11_server_handshake_with_ecc_sm4_cbc_sm3() throws IOException {

        String url = "https://localhost:5443";
        TestHelper.sendAsyncConnectTLCPServer(url);
        int port = 5443;


        ServerSocket serverSocket = new ServerSocket(port);

        Socket socket = serverSocket.accept();

        PeerInfoProvider peerInfoProvider = new PeerInfoProvider() {
            @Override
            public String getHostname() {
                return socket.getInetAddress().getHostName();
            }

            @Override
            public int getPort() {
                return socket.getPort();
            }
        };

        gmKaiSSLParameters.setUseClientMode(false);
        SChannel sChannel = new SChannel(
                tlsEventBus,
                internalContextData,
                gmKaiSSLParameters, peerInfoProvider, socket.getInputStream(), socket.getOutputStream());

        sChannel.startHandshake();
        assertThat(sChannel.getHandshakeSession().getCipherSuite(),
                is(ECC_SM4_CBC_SM3.name));
    }

    private static InternalContextData createTextInternalContextData() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, NoSuchProviderException, IOException {

        InternalContextData internalContextData = mock(InternalContextData.class);
        when(internalContextData.getSecureRandom()).thenReturn(new SecureRandom());
        when(internalContextData.getTLSCrypto()).thenReturn(new BcTLSCrypto());
        when(internalContextData.getKeyManager()).thenReturn(new MyInternalTLCPX509KeyManager());
        when(internalContextData.getTrustManager()).thenReturn(new TrustAllManager());
        return internalContextData;
    }

    private static class TrustAllManager implements InternalX509TrustManager {

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {

        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {

        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            throw new UnsupportedOperationException();
        }
    }


    private static class MyInternalTLCPX509KeyManager implements InternalTLCPX509KeyManager {

        KeyStore sm2KeyStore = TestHelper.getKeyStore("src/test/resources/sm2.gmkai.pfx", "12345678");

        private MyInternalTLCPX509KeyManager() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, NoSuchProviderException, IOException {
        }

        @Override
        public String[] getClientAliases(String keyType, Principal[] issuers) {
            return new String[0];
        }

        @Override
        public String[] getServerAliases(String keyType, Principal[] issuers) {
            return new String[0];
        }

        @Override
        public PrivateKey getPrivateKey(String alias) {
            try {
                return (PrivateKey) sm2KeyStore.getKey(alias, "12345678".toCharArray());
            } catch (Exception e) {
                throw new RuntimeException(e.getMessage(), e);
            }
        }

        @Override
        public String chooseClientSigAlias(String[] keyType, Principal[] issuers) {
            return "sig";
        }

        @Override
        public String chooseClientEncAlias(String[] keyType, Principal[] issuers) {
            return "enc";
        }

        @Override
        public String chooseServerSigAlias(String keyType, Principal[] issuers) {
            return "sig";
        }

        @Override
        public String chooseServerEncAlias(String keyType, Principal[] issuers) {
            return "enc";
        }

        @Override
        public X509Certificate[] getCertificateChain(String sigAlias, String encAlias) {
            try {
                return new X509Certificate[]{(X509Certificate) sm2KeyStore.getCertificate(sigAlias), (X509Certificate) sm2KeyStore.getCertificate(encAlias)};
            } catch (Exception e) {
                throw new RuntimeException(e.getMessage(), e);
            }
        }
    }


}
