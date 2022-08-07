package com.tianpengfei.gmkai.util.bc;

import com.tianpengfei.gmkai.util.bc.cert.SM2CertUtil;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.*;
import java.util.ArrayList;
import java.util.List;

/**
 * @author tianpengfei
 * @since 2022-02-14 15:04:03
 */
public class GMHttpUtils {
    private static X9ECParameters x9ECParameters = GMNamedCurves.getByName("sm2p256v1");
    private static ECDomainParameters ecDomainParameters = new ECDomainParameters(x9ECParameters.getCurve(),
            x9ECParameters.getG(), x9ECParameters.getN());

    public static byte[] encrypt(BCECPublicKey key, byte[] preMasterSecret)
            throws IOException, InvalidCipherTextException {
        ECPublicKeyParameters publicKeyParameters = new ECPublicKeyParameters(key.getQ(), ecDomainParameters);
        SM2Engine sm2Engine = new SM2Engine(SM2Engine.Mode.C1C3C2);
        sm2Engine.init(true, new ParametersWithRandom(publicKeyParameters, new SecureRandom()));
        byte[] c1c3c2 = sm2Engine.processBlock(preMasterSecret, 0, preMasterSecret.length);

        final int c1Len = (x9ECParameters.getCurve().getFieldSize() + 7) / 8 * 2 + 1; // sm2p256v1的这个固定65。可看GMNamedCurves、ECCurve代码。
        final int c3Len = 32; // new SM3Digest().getDigestSize();
        byte[] c1x = new byte[32];
        // 第一个字节为固定的 0x04
        System.arraycopy(c1c3c2, 1, c1x, 0, 32); // c1x
        byte[] c1y = new byte[32];
        System.arraycopy(c1c3c2, c1x.length + 1, c1y, 0, 32); // c1y

        // 32 字节的签名
        byte[] c3 = new byte[c3Len];
        System.arraycopy(c1c3c2, c1Len, c3, 0, c3Len); // c3

        // 被加密的字节，长度与加密前的字节一致
        int c2len = c1c3c2.length - c1Len - c3Len;
        byte[] c2 = new byte[c2len];
        System.arraycopy(c1c3c2, c1Len + c3Len, c2, 0, c2len); // c2

        // 重新编码为 ASN1 格式
        return encode(c1x, c1y, c3, c2);
    }

    public static byte[] encode(byte[] c1x, byte[] c1y, byte[] c3, byte[] c2) throws IOException {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new ASN1Integer(c1x));
        v.add(new ASN1Integer(c1y));
        v.add(new DEROctetString(c3));
        v.add(new DEROctetString(c2));
        DERSequence seq = new DERSequence(v);
        return seq.getEncoded();
    }

    private static byte[] join(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    private static void hmacHash(byte[] secret, byte[] seed, byte[] output) {
        KeyParameter keyParameter = new KeyParameter(secret);
        SM3Digest digest = new SM3Digest();
        HMac mac = new HMac(digest);
        mac.init(keyParameter);

        byte[] a = seed;

        int macSize = mac.getMacSize();

        byte[] b1 = new byte[macSize];
        byte[] b2 = new byte[macSize];

        int pos = 0;
        while (pos < output.length) {
            mac.update(a, 0, a.length);
            mac.doFinal(b1, 0);
            a = b1;
            mac.update(a, 0, a.length);
            mac.update(seed, 0, seed.length);
            mac.doFinal(b2, 0);
            System.arraycopy(b2, 0, output, pos, Math.min(macSize, output.length - pos));
            pos += macSize;
        }
    }

    /**
     * PRF实现
     */
    public static byte[] prf(byte[] secret, byte[] label, byte[] seed, int length) {
        byte[] labelSeed = join(label, seed);
        byte[] result = new byte[length];
        hmacHash(secret, labelSeed, result);
        return result;
    }

    public static byte[] hash(byte[] bytes) {
        Digest digest = new SM3Digest();
        byte[] output = new byte[digest.getDigestSize()];
        digest.update(bytes, 0, bytes.length);
        digest.doFinal(output, 0);
        return output;
    }

    public static X509Certificate getTrustedX509CertificateFromPEM(String certPath) throws IOException, CertificateException {

        CertificateFactory cf = CertificateFactory.getInstance("X.509", Security.getProvider("BC"));
        FileInputStream is = new FileInputStream(certPath);
        return (X509Certificate) cf.generateCertificate(is);
    }

    public static void checkCertChain(List<X509Certificate> trustedChain) throws CertificateException {
        for (int i = 1; i < trustedChain.size(); i++) {
            try {
                trustedChain.get(i - 1).verify(trustedChain.get(i).getPublicKey());
            } catch (NoSuchAlgorithmException | InvalidKeyException | NoSuchProviderException | SignatureException | CertificateException e) {
                throw new CertificateException(e.toString());
            }
        }
    }

    public static void checkTrusted(X509Certificate sig, X509Certificate enc, List<X509Certificate> ca) throws CertificateException {

        sig.checkValidity();
        enc.checkValidity();

        PublicKey publicKey = ca.get(0).getPublicKey();

        //校验签名证书、校验加密证书
        try {
            sig.verify(publicKey);
            enc.verify(publicKey);
        } catch (NoSuchAlgorithmException | InvalidKeyException | NoSuchProviderException | SignatureException e) {
            throw new CertificateException(e.toString(), e);
        }

    }

    public static void checkTrusted(List<X509Certificate> chain,
                                    List<X509Certificate> trustedChain) throws CertificateException {

        if (chain.size() != 2) {
            throw new CertificateException("要校验的证书的数量等于2（签名证书+加密证书）");
        }
        chain.get(0).checkValidity();
        chain.get(1).checkValidity();

        PublicKey publicKey = trustedChain.get(0).getPublicKey();

        //校验签名证书、校验加密证书
        try {
            chain.get(0).verify(publicKey);
            chain.get(1).verify(publicKey);
        } catch (NoSuchAlgorithmException | InvalidKeyException | NoSuchProviderException | SignatureException e) {
            throw new CertificateException(e.toString());
        }

    }

    public static CertPath getCertPath(KeyStore keyStore, String alias) throws KeyStoreException, CertificateException, NoSuchProviderException {
        Certificate[] certChain = keyStore.getCertificateChain(alias);
        List<X509Certificate> serverCertChain = new ArrayList<>();
        for (Certificate certificate : certChain) {
            serverCertChain.add((X509Certificate) certificate);
        }
        return SM2CertUtil.getCertificateChain(serverCertChain);
    }

    public static byte[] combinationBytes(byte[]... bytes) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] by : bytes) {
            out.write(by);
        }
        return out.toByteArray();
    }

    public static byte[] combinationBytes(List<byte[]> bytes) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] by : bytes) {
            out.write(by);
        }
        return out.toByteArray();
    }
}