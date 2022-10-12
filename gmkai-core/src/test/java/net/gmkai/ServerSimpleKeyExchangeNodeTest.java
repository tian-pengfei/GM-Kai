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

public class ServerSimpleKeyExchangeNodeTest {

    private HandshakeContext handshakeContext;

    private X509Certificate[] sm2Chain;

    private PrivateKey sm2SignKey;

    private X509Certificate[] rsaChain;

    private PrivateKey rsaSignKey;

    private TLCPX509Possession sm2Possession;

    private TLCPX509Possession rsaPossession;


    @BeforeEach
    public void setUp() throws Exception {

        this.handshakeContext = mock(HandshakeContext.class);

        KeyStore sm2KeyStore = TestHelper.getKeyStore("src/test/resources/sm2.gmkai.pfx", "12345678");

        this.sm2Chain = new X509Certificate[]{(X509Certificate) sm2KeyStore.getCertificate("sig"), (X509Certificate) sm2KeyStore.getCertificate("enc")};
        PrivateKey sm2SignKey = (PrivateKey) sm2KeyStore.getKey("sig", "12345678".toCharArray());
        PrivateKey sm2EncKey = (PrivateKey) sm2KeyStore.getKey("enc", "12345678".toCharArray());
        this.sm2Possession = new TLCPX509Possession(sm2Chain, sm2SignKey, sm2EncKey);

        KeyStore rsaKeyStore = TestHelper.getKeyStore("src/test/resources/rsa.gmkai.pfx", "12345678");
        this.rsaChain = new X509Certificate[]{(X509Certificate) rsaKeyStore.getCertificate("keypair"), (X509Certificate) rsaKeyStore.getCertificate("keypair")};
        PrivateKey rsaKey = (PrivateKey) rsaKeyStore.getKey("keypair", "12345678".toCharArray());
        this.rsaPossession = new TLCPX509Possession(rsaChain, rsaKey, rsaKey);

        when(handshakeContext.getServerRandom()).thenReturn(new byte[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0});
        when(handshakeContext.getClientRandom()).thenReturn(new byte[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0});
        when(handshakeContext.getTLSCrypto()).thenReturn(new BcTLSCrypto());
    }

    @Test
    public void should_server_product_ecc_key_change_message() throws IOException {
        should_server_product_simple_key_change_message(sm2Possession, TLSCipherSuite.ECC_SM4_CBC_SM3, sm2Chain);
    }

    @Test
    public void should_client_consume_ecc_key_change_message() throws IOException {

        byte[] message = Hexs.decode("00463044022047c35c9ff6ab7e282f0a5b999527f97e903a593e3b80ba02ee57b7912f2b172d0220759658af8ecf0f2c4081e49025923194d1fac8bb4ca015a0b762e7bbf08fc6e7");
        should_client_consume_simple_key_exchange(TLSCipherSuite.ECC_SM4_CBC_SM3, sm2Chain, message);

    }

    @Test
    public void should_server_product_rsa_key_change_message() throws IOException {

        should_server_product_simple_key_change_message(rsaPossession, TLSCipherSuite.RSA_SM4_CBC_SHA256, rsaChain);
    }

    @Test
    public void should_client_consume_rsa_key_change_message() throws IOException {

        byte[] message = Hexs.decode("010007ea59a2db65bee16e4d36d55c593988060b2e8a8f314a0ebe3f576d048646b11732c06323bd93282a369e90e3daaaa86ebe3a8d66cf6c672664ef5f4f451188bcf3295db7fe5e9572487dfd293748882fac3402f3a205a4bd7f14217c0a6f42ab8f2205f1a3db2df2cd3d4f13509d52ff8c452a7dd00602e7938d96e679a9f87edd002520c83a686675f080f1c633435d86545754bfc72761195c50015caa9d7621b852bde0d620a4230e617ee3306f7f6f4d0740be2b44e60dd1eb1bbf68a27ff08585f1c34134ef7c3900d55cc58727210ef5dc7a8f775f92ec49a98e3a44e45d7d414287d39e7fa9cf8fa569e284f0b8bdfa2c9575ba7949eba0a7a31c7b");
        should_client_consume_simple_key_exchange(TLSCipherSuite.RSA_SM4_CBC_SHA256, rsaChain, message);
    }

    private void should_client_consume_simple_key_exchange(TLSCipherSuite tlsCipherSuite, X509Certificate[] chain, byte[] message) throws IOException {
        ServerSimpleKeyExchangeNode serverECCKeyExchangeNode = new ServerSimpleKeyExchangeNode();

        InternalTLCPX509KeyManager internalTLCPX509KeyManager = mock(InternalTLCPX509KeyManager.class);

        when(handshakeContext.getKeyManager()).thenReturn(internalTLCPX509KeyManager);
        when(handshakeContext.getCurrentCipherSuite()).thenReturn(tlsCipherSuite);
        when(handshakeContext.isClientMode()).thenReturn(true);
        when(handshakeContext.getPeerCertChain()).thenReturn(chain);
        serverECCKeyExchangeNode.doConsume(handshakeContext, message);
    }


    public void should_server_product_simple_key_change_message(TLCPX509Possession possession, TLSCipherSuite tlsCipherSuite, X509Certificate[] chain) throws IOException {

        ServerSimpleKeyExchangeNode serverECCKeyExchangeNode = new ServerSimpleKeyExchangeNode();

        when(handshakeContext.getTLCPX509Possession()).thenReturn(possession);
        when(handshakeContext.getCurrentCipherSuite()).thenReturn(tlsCipherSuite);
        when(handshakeContext.isClientMode()).thenReturn(false);
        when(handshakeContext.getLocalCertChain()).thenReturn(chain);

        serverECCKeyExchangeNode.doProduce(handshakeContext);
    }
}
