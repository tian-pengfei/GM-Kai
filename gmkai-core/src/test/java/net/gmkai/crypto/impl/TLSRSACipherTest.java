package net.gmkai.crypto.impl;

import net.gmkai.crypto.AsymmetricBlockPadding;
import net.gmkai.crypto.TLSCrypto;
import net.gmkai.crypto.TLSRSACipher;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import test.TestHelper;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;


public abstract class TLSRSACipherTest {

    final private byte[] src = "Hello GMKai!".getBytes(StandardCharsets.UTF_8);

    private RSAPrivateKey priKey;

    private RSAPublicKey pubKey;

    final private TLSCrypto tlsCrypto;

    protected TLSRSACipherTest(TLSCrypto tlsCrypto) {
        this.tlsCrypto = tlsCrypto;
    }

    @BeforeEach
    public void setup() throws Exception {

        String priKeyFilePath = "src/test/resources/rsa.pri.key.pem";
        priKey = (RSAPrivateKey) TestHelper.decodePrivateKey(priKeyFilePath);

        String pubKeyFilePath = "src/test/resources/rsa.pub.key.pem";
        pubKey = (RSAPublicKey) TestHelper.decodePublicKey(pubKeyFilePath);

    }

    @Test
    public void should_rsa_encrypt_with_PKCS1Padding() throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException, InvalidKeyException {

        TLSRSACipher tlsrsaCipher =
                tlsCrypto.getTLSRSACipher(true, AsymmetricBlockPadding.PKCS1Padding, pubKey);

        byte[] encryptedText = tlsrsaCipher.processBlock(src, 0, src.length);

        assertThat(TestHelper.rsaDecrypt(priKey, encryptedText), is(src));
    }

    @Test
    public void should_rsa_decrypt_with_PKCS1Padding() throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException, InvalidKeyException {
        byte[] encryptedText = TestHelper.rsaEncrypt(pubKey, src);

        TLSRSACipher tlsrsaCipher =
                tlsCrypto.getTLSRSACipher(false, AsymmetricBlockPadding.PKCS1Padding, priKey);

        byte[] text = tlsrsaCipher.processBlock(encryptedText, 0, encryptedText.length);

        assertThat(text, is(src));

    }
}
