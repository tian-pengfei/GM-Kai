package net.gmkai.crypto.impl;

import net.gmkai.util.Hexs;
import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

public abstract class TLSBlockCipherImplTest {

    final private TLSBlockCipherImpl sm4Encrypt;

    final private TLSBlockCipherImpl sm4Decrypt;


    final private static byte[] sm4Key = Hexs.decode("57f60a8036f3d35d62f23fefca74c203");

    final private static byte[] sm4Iv = Hexs.decode("4b1fa25e86ba0fe789654179d539fb3d");

    final private static byte[] data = Hexs.decode("474d4b61692109090909090909090909");

    final private static byte[] encryptData = Hexs.decode("1738f4813f63c7b5d863ec1efe0f0056");


    public TLSBlockCipherImplTest(TLSBlockCipherImpl sm4Encrypt, TLSBlockCipherImpl sm4Decrypt) throws IOException {
        this.sm4Encrypt = sm4Encrypt;
        this.sm4Decrypt = sm4Decrypt;
        this.sm4Encrypt.setKey(sm4Key, 0, sm4Key.length);
        this.sm4Encrypt.init(sm4Iv, 0, sm4Iv.length);
        this.sm4Decrypt.setKey(sm4Key, 0, sm4Key.length);
        this.sm4Decrypt.init(sm4Iv, 0, sm4Iv.length);


    }


    @Test
    public void should_sm4_decrypt() throws IOException {

        byte[] output = new byte[encryptData.length];
        int decryptLength = sm4Decrypt.doFinal(encryptData, 0, encryptData.length, output, 0);
        assertThat(decryptLength, is(output.length));
        assertThat(output, is(data));

    }

    @Test
    public void should_sm4_encrypt() throws IOException {

        byte[] output = new byte[data.length];
        int encryptLength = sm4Encrypt.doFinal(data, 0, data.length, output, 0);
        assertThat(encryptLength, is(output.length));
        assertThat(output, is(encryptData));

    }


    @Test
    public void should_block_size() {
        assertThat(sm4Decrypt.getBlockSize(), is(16));
    }


}
