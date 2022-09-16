package net.gmkai.crypto.impl;

import net.gmkai.crypto.TLSCrypto;
import net.gmkai.crypto.TLSSM2Cipher;
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
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

public abstract class TLSSM2CipherTest {

    final private byte[] src = "Hello GMKai!".getBytes(StandardCharsets.UTF_8);

    private ECPrivateKey priKey;

    private ECPublicKey pubKey;

    final private TLSCrypto tlsCrypto;

    protected TLSSM2CipherTest(TLSCrypto tlsCrypto) {
        this.tlsCrypto = tlsCrypto;
    }

    @BeforeEach
    public void setup() throws Exception {

        String priKeyFilePath = "src/test/resources/sm2.pri.key.pem";
        priKey = (ECPrivateKey) TestHelper.decodePrivateKey(priKeyFilePath);

        String pubKeyFilePath = "src/test/resources/sm2.pub.key.pem";
        pubKey = (ECPublicKey) TestHelper.decodePublicKey(pubKeyFilePath);

    }

    @Test
    public void should_sm2_encrypt() throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException, InvalidKeyException {

        TLSSM2Cipher tlssm2Cipher =
                tlsCrypto.getTLSSM2Cipher(true, pubKey);

        byte[] encryptedText = tlssm2Cipher.processBlock(src, 0, src.length);

        byte[] text = TestHelper.sm2Decrypt(priKey, encryptedText);
        assertThat(text, is(src));

    }

    @Test
    public void should_sm2_decrypt() throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException, InvalidKeyException {

        byte[] encryptedText = TestHelper.sm2Encrypt(pubKey, src);

        TLSSM2Cipher tlssm2Cipher =
                tlsCrypto.getTLSSM2Cipher(false, priKey);
        byte[] text = tlssm2Cipher.processBlock(encryptedText, 0, encryptedText.length);

        assertThat(text, is(src));

    }

}
