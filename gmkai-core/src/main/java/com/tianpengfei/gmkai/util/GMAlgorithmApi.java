package com.tianpengfei.gmkai.util;

import com.tianpengfei.gmkai.util.bc.*;
import org.bouncycastle.crypto.CryptoException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.net.ssl.SSLException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * @author tianpengfei
 * @since 2022-05-12 17:00:03
 */
public interface GMAlgorithmApi {

    static final SecureRandom secureRandom = new SecureRandom();

    static SecureRandom getRandom() {
        return secureRandom;
    }

    static byte[][] generateSm2KeyPair() {
        return SM2Util.generateRawKeyPair(secureRandom);
    }


    static byte[] sm2Sign(byte[] priKey, byte[] withId, byte[] srcData) throws SSLException {
        try {
            return SM2Util.sign(BCECUtil.convertRawPrivateKeyToParameters(priKey), withId, srcData);
        } catch (CryptoException e) {
            throw new SSLException(e.getMessage(), e);
        }
    }


    static byte[] sm2ECDH(boolean initiator, int length, byte[] selfPriKey, byte[] selfTmpPriKey, byte[] selfId, byte[] peerPubKey, byte[] peerTmpPub, byte[] peerId) throws SSLException {

        return SM2KeyExchangeUtil.calculateKey(
                initiator,
                length,
                BCECUtil.convertRawPrivateKeyToParameters(selfPriKey),
                BCECUtil.convertRawPrivateKeyToParameters(selfTmpPriKey),
                selfId,
                BCECUtil.convertPublicKeySRawToParams(peerPubKey),
                BCECUtil.convertPublicKeySRawToParams(peerTmpPub),
                peerId);
    }


    static byte[] prf(byte[] secret, byte[] label, byte[] seed, int length) throws SSLException {
        return GMHttpUtils.prf(secret, label, seed, length);
    }


    static boolean sm2Verify(byte[] pubKey, byte[] withId, byte[] srcData, byte[] sign) throws SSLException {
        return SM2Util.verify(BCECUtil.convertPublicKeySRawToParams(pubKey), withId, srcData, sign);
    }


    static byte[] sm3Hash(byte[] srcData) throws SSLException {
        return SM3Util.hash(srcData);
    }


    static byte[] sm3Hmac(byte[] key, byte[] srcData) throws SSLException {
        return SM3Util.hmac(key, srcData);
    }


    static void checkTrusted(X509Certificate signCert, X509Certificate encCert, List<X509Certificate> ca) throws SSLException {

        try {
            GMHttpUtils.checkTrusted(signCert, encCert, ca);
        } catch (CertificateException e) {
            throw new SSLException(e.getMessage(), e);
        }
    }


    static byte[] sm4EncryptECBPadding(byte[] key, byte[] data) throws SSLException {
        try {
            return SM4Util.encrypt_ECB_Padding(key, data);
        } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException | NoSuchProviderException e) {
            throw new SSLException(e.getMessage(), e);
        }
    }


    static byte[] sm4DecryptECBPadding(byte[] key, byte[] encodedText) throws SSLException {
        try {
            return SM4Util.decrypt_ECB_Padding(key, encodedText);
        } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException | NoSuchProviderException e) {
            throw new SSLException(e.getMessage(), e);
        }
    }
}
