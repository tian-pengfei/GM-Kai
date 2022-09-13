package net.gmkai.crypto.impl;

import net.gmkai.crypto.*;
import net.gmkai.util.Hexs;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

public abstract class TLSCryptoTest {


    private final TLSCrypto tlsCrypto;

    public TLSCryptoTest(TLSCrypto tlsCrypto) {
        this.tlsCrypto = tlsCrypto;
    }

    private final static byte[] src = "Hello GMKai!".getBytes(StandardCharsets.UTF_8);

    private final static byte[] hmac_key = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};

    private final static byte[] sm3_hmac = Hexs.decode("bc3cd4c88c1494d9a2c9d84a6dffb05fd8b9ee73eeca249cf3c2f133be55f3d5");

    private final static byte[] sha256_hmac = Hexs.decode("2dc253c580760f202bb7bb210af3d925e80f0acd26225fd234027c1ca6f513f8");

    private final static byte[] sm3_hash = Hexs.decode("607B6546BCD39996925E669C23478DDD9EE5CFBE13348B5E8789B2800E9B40FD");

    private final static byte[] sha256_hash = Hexs.decode("2a795f2afe9d521917939214e509a9a0617695f5e213596e62b9d6648e30e691");


    private static void assertHMac(TLSHMac tlshMac, byte[] macResult) {

        tlshMac.setKey(hmac_key, 0, hmac_key.length);
        tlshMac.update(src, 0, src.length);
        assertThat(tlshMac.calculateMAC(), is(macResult));
    }

    private static void assertAcquireHMacByOutput(TLSHMac tlshMac, byte[] macResult) {

        tlshMac.setKey(hmac_key, 0, hmac_key.length);
        tlshMac.update(src, 0, src.length);
        byte[] output = new byte[macResult.length];
        tlshMac.calculateMAC(output, 0);
        assertThat(output, is(macResult));
    }

    private static void assertHash(TLSHash tlsHash, byte[] hashResult) {

        tlsHash.update(src, 0, src.length);
        assertThat(tlsHash.calculateHash(), is(hashResult));
    }

    private static void assertAcquireHashByOutput(TLSHash tlsHash, byte[] hashResult) {

        tlsHash.update(src, 0, src.length);
        byte[] output = new byte[hashResult.length];
        tlsHash.calculateHash(output, 0);
        assertThat(output, is(hashResult));
    }

    @Test
    public void should_return_expected_sm3_hmac() {

        TLSHMac tlshMac = tlsCrypto.createHMAC(MacAlg.M_SM3);
        assertHMac(tlshMac, sm3_hmac);
    }

    @Test
    public void should_acquire_expected_sm3_hmac_by_output() {

        TLSHMac tlshMac = tlsCrypto.createHMAC(MacAlg.M_SM3);

        assertAcquireHMacByOutput(tlshMac, sm3_hmac);
    }

    @Test
    public void should_return_expected_sm3_hmac_after_reset() {

        TLSHMac tlshMac = tlsCrypto.createHMAC(MacAlg.M_SM3);
        tlshMac.update(src, 0, src.length);
        tlshMac.reset();
        assertHMac(tlshMac, sm3_hmac);
    }

    @Test
    public void should_return_expected_sha256_hmac() {

        TLSHMac tlshMac = tlsCrypto.createHMAC(MacAlg.M_SHA256);
        assertHMac(tlshMac, sha256_hmac);

    }

    @Test
    public void should_acquire_expected_sha256_hmac_by_output() {

        TLSHMac tlshMac = tlsCrypto.createHMAC(MacAlg.M_SHA256);

        assertAcquireHMacByOutput(tlshMac, sha256_hmac);
    }

    @Test
    public void should_return_expected_sha256_hmac_after_reset() {

        TLSHMac tlshMac = tlsCrypto.createHMAC(MacAlg.M_SHA256);
        tlshMac.update(src, 0, src.length);
        tlshMac.reset();
        assertHMac(tlshMac, sha256_hmac);

    }

    @Test
    public void should_return_expected_sm3_hash() {

        TLSHash tlsHash = tlsCrypto.createHash(HashAlg.H_SM3);
        assertHash(tlsHash, sm3_hash);
    }

    @Test
    public void should_return_expected_sm3_hash_after_reset() {

        TLSHash tlsHash = tlsCrypto.createHash(HashAlg.H_SM3);
        tlsHash.update(src, 0, src.length);
        tlsHash.reset();
        assertHash(tlsHash, sm3_hash);
    }

    @Test
    public void should_acquire_expected_sm3_hash_by_output() {

        TLSHash tlsHash = tlsCrypto.createHash(HashAlg.H_SM3);

        assertAcquireHashByOutput(tlsHash, sm3_hash);
    }

    @Test
    public void should_return_expected_sha256_hash() {

        TLSHash tlsHash = tlsCrypto.createHash(HashAlg.H_SHA256);
        assertHash(tlsHash, sha256_hash);
    }

    @Test
    public void should_return_expected_sha256_hash_after_reset() {

        TLSHash tlsHash = tlsCrypto.createHash(HashAlg.H_SHA256);
        tlsHash.update(src, 0, src.length);
        tlsHash.reset();
        assertHash(tlsHash, sha256_hash);
    }

    @Test
    public void should_acquire_expected_sha256_hash_by_output() {

        TLSHash tlsHash = tlsCrypto.createHash(HashAlg.H_SHA256);

        assertAcquireHashByOutput(tlsHash, sha256_hash);
    }

    @Test
    public void should_acquire_SM3WITHSM2_TLSSigner() throws IOException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, SignatureException, NoSuchProviderException, InvalidKeyException {

        testSigner("EC", new ECGenParameterSpec("sm2p256v1"), SignatureAndHashAlg.SM2SIG_SM3);
    }

    @Test
    public void should_acquire_SHA256WITHRSA_TLSSigner() throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, InvalidAlgorithmParameterException {

        testSigner("RSA", new RSAKeyGenParameterSpec(512, RSAKeyGenParameterSpec.F4), SignatureAndHashAlg.RSA_SHA256);

    }

    private void testSigner(String name, AlgorithmParameterSpec parameterSpec,
                            SignatureAndHashAlg signatureAndHashAlg) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, IOException {
        KeyPair keyPair =
                generateKeyPair(name, parameterSpec);

        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        TLSSigner tlsSigner = tlsCrypto.getTLSSigner(privateKey, signatureAndHashAlg);
        tlsSigner.addData(src);

        Signature signature = Signature.getInstance(signatureAndHashAlg.jceName, new BouncyCastleProvider());
        signature.initVerify(publicKey);
        signature.update(src);
        assertThat(signature.verify(tlsSigner.getSignature()), is(true));
    }

    @Test
    public void should_acquire_SHA256WITHRSA_TLSSignVerifier() throws Exception {
        testSignVerifier("RSA", new RSAKeyGenParameterSpec(512, RSAKeyGenParameterSpec.F4), SignatureAndHashAlg.RSA_SHA256);
    }

    @Test
    public void should_acquire_SM3WITHSM2_TLSSignVerifier() throws Exception {

        testSignVerifier("EC", new ECGenParameterSpec("sm2p256v1"), SignatureAndHashAlg.SM2SIG_SM3);

    }

    private void testSignVerifier(String name, AlgorithmParameterSpec parameterSpec,
                                  SignatureAndHashAlg signatureAndHashAlg) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, IOException {
        KeyPair keyPair =
                generateKeyPair(name, parameterSpec);

        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        TLSSignatureVerifier tlsSignatureVerifier =
                tlsCrypto.getTLSSignatureVerifier(publicKey, signatureAndHashAlg);
        tlsSignatureVerifier.addData(src);

        Signature signature = Signature.getInstance(signatureAndHashAlg.jceName, new BouncyCastleProvider());
        signature.initSign(privateKey);
        signature.update(src);
        assertThat(tlsSignatureVerifier.verifySignature(signature.sign()), is(true));
    }

    private KeyPair generateKeyPair(String name, AlgorithmParameterSpec parameterSpec) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {

        SecureRandom secureRandom = new SecureRandom();
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(name, new BouncyCastleProvider());
        keyPairGenerator.initialize(parameterSpec, secureRandom);
        return keyPairGenerator.generateKeyPair();
    }

}
