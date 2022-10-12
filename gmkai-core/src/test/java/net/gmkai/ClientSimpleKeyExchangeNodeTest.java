package net.gmkai;

import net.gmkai.crypto.impl.bc.BcTLSCrypto;
import net.gmkai.util.Hexs;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import test.TestHelper;

import java.io.IOException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class ClientSimpleKeyExchangeNodeTest {


    private HandshakeContext handshakeContext;

    private X509Certificate[] sm2Chain;

    private X509Certificate[] rsaChain;

    private TLCPX509Possession sm2Possession;

    private TLCPX509Possession rsaPossession;

    byte[] sm2_client_key_exchange_msg = Hexs.decode("00 9b 30 81 98 02 20 a9 76 a3 24 e1\n" +
            "   51 75 ef 89 a7 61 7e 61 a3 86 29 40 6a 65 93 da\n" +
            "   e4 77 ad d9 d4 6d 7d 8b 73 46 73 02 20 b5 11 0e\n" +
            "   31 8c 7a 2d d5 61 a2 c9 cc d4 60 b3 09 7e 1d 40\n" +
            "   7f b8 fb c6 83 5e e0 e5 77 85 31 12 1d 04 20 41\n" +
            "   26 25 d2 66 00 41 42 e2 25 65 6d 89 3b 17 f7 b9\n" +
            "   eb 87 76 5e dc 1b 7c 52 29 d7 78 c6 65 da 78 04\n" +
            "   30 c9 2c f1 af c8 24 12 e3 40 76 c9 3d 97 ac 49\n" +
            "   6a dc 01 ca 4a 31 4e 8d 5d 76 69 3b c2 39 56 ea\n" +
            "   f1 3b 2f 3e 9e 42 c4 fa 4f d4 94 df 93 a3 1b 38\n" +
            "   1c");

    @BeforeEach
    public void setUp() throws Exception {

        this.handshakeContext = mock(HandshakeContext.class);

        KeyStore sm2KeyStore = TestHelper.getKeyStore("src/test/resources/sm2.gmkai.pfx", "12345678");

        this.sm2Chain = new X509Certificate[]{(X509Certificate) sm2KeyStore.getCertificate("sig"), (X509Certificate) sm2KeyStore.getCertificate("enc")};

        PrivateKey sm2EncKey = (PrivateKey) sm2KeyStore.getKey("enc", "12345678".toCharArray());

        PrivateKey sm2SigKey = (PrivateKey) sm2KeyStore.getKey("sin", "12345678".toCharArray());
        this.sm2Possession = new TLCPX509Possession(sm2Chain, sm2SigKey, sm2EncKey);

        KeyStore rsaKeyStore = TestHelper.getKeyStore("src/test/resources/rsa.gmkai.pfx", "12345678");
        this.rsaChain = new X509Certificate[]{(X509Certificate) rsaKeyStore.getCertificate("keypair"), (X509Certificate) rsaKeyStore.getCertificate("keypair")};
        PrivateKey rsaKey = (PrivateKey) rsaKeyStore.getKey("keypair", "12345678".toCharArray());
        this.rsaPossession = new TLCPX509Possession(rsaChain, rsaKey, rsaKey);

        when(handshakeContext.getTLSCrypto()).thenReturn(new BcTLSCrypto());
        when(handshakeContext.getCurrentProtocol()).thenReturn(ProtocolVersion.TLCP11);
    }

    @Test
    public void should_product_client_ecc_key_change_message() throws IOException {

        should_product_client_key_change_message(TLSCipherSuite.ECC_SM4_CBC_SM3, sm2Chain);
    }


    @Test
    public void should_consume_client_ecc_key_change_message() throws IOException {
        should_consume_client_key_change_message(TLSCipherSuite.ECC_SM4_CBC_SM3, sm2Possession, sm2_client_key_exchange_msg);
    }

    @Test
    public void should_product_client_rsa_key_change_message() throws IOException {
        should_product_client_key_change_message(TLSCipherSuite.RSA_SM4_CBC_SHA256, rsaChain);
    }


    @Test
    public void should_consume_client_rsa_key_change_message() throws IOException {
        byte[] message = Hexs.decode("01009f36729afe04774b111e4a977dc3aa01f6d5fce554b113b6b08387e5dd17cc0fb63fbd5ce4c40ebe8c9b673aad7f7807e5a5f96c473dc6d5546e72c7de1b493969d4e1eb0885effb31bc5950be0c17c44519412ef8453d9db8ea61194cc543382cf5d98dda647f1430db292eafca8add2eb6f4414765c0b370cedbb50d6ac358a7d9924239f3edf22e4025ac12b0a32577d5cd1d5cdfdc63e6e65e19c616e0310e8381c1785c192a6da18b31d22e499246c62e69352ac8e1dc36095d9d9d3752893bdb9441d0e60e0b6dc92da376ca86f3264d31c181fc4d7a29df7d35d7a1ce9f64ba34d89e2e6364cf80e171748fbc037c82ac53635793613456a85aa81282");

        should_consume_client_key_change_message(TLSCipherSuite.RSA_SM4_CBC_SHA256, rsaPossession, message);
    }

    private void should_product_client_key_change_message(TLSCipherSuite tlsCipherSuite, X509Certificate[] chain) throws IOException {

        ClientSimpleKeyExchangeNode clientSimpleKeyExchangeNode = new ClientSimpleKeyExchangeNode();
        when(handshakeContext.getCurrentCipherSuite()).thenReturn(tlsCipherSuite);
        when(handshakeContext.isClientMode()).thenReturn(true);
        when(handshakeContext.getPeerCertChain()).thenReturn(chain);
        clientSimpleKeyExchangeNode.doProduce(handshakeContext).getBody();

    }


    public void should_consume_client_key_change_message(TLSCipherSuite tlsCipherSuite, TLCPX509Possession possession, byte[] message) throws IOException {

        ClientSimpleKeyExchangeNode clientSimpleKeyExchangeNode = new ClientSimpleKeyExchangeNode();
        when(handshakeContext.getCurrentCipherSuite()).thenReturn(tlsCipherSuite);
        when(handshakeContext.isClientMode()).thenReturn(false);

        when(handshakeContext.getTLCPX509Possession()).thenReturn(possession);

        clientSimpleKeyExchangeNode.doConsume(handshakeContext, message);

    }


}
