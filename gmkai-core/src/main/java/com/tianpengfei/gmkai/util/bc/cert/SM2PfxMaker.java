package com.tianpengfei.gmkai.util.bc.cert;

import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.engines.RC2Engine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.pkcs.*;
import org.bouncycastle.pkcs.bc.BcPKCS12MacCalculatorBuilder;
import org.bouncycastle.pkcs.bc.BcPKCS12PBEOutputEncryptorBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS12SafeBagBuilder;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

public class SM2PfxMaker {

    /**
     * @param priKey 用户私钥
     * @param pubKey 用户公钥
     * @param chain  X509证书数组，切记这里固定了必须是3个元素的数组，且第一个必须是叶子证书、第二个为中级CA证书、第三个为根CA证书
     * @param passwd 口令
     * @return
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws PKCSException
     */
    public PKCS12PfxPdu makePfx(PrivateKey priKey, PublicKey pubKey, X509Certificate[] chain, String passwd)
            throws NoSuchAlgorithmException, IOException, PKCSException {
        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();

        PKCS12SafeBagBuilder taCertBagBuilder = new JcaPKCS12SafeBagBuilder(chain[2]);
        taCertBagBuilder.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName,
                new DERBMPString("Primary Certificate"));

        PKCS12SafeBagBuilder caCertBagBuilder = new JcaPKCS12SafeBagBuilder(chain[1]);
        caCertBagBuilder.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName,
                new DERBMPString("Intermediate Certificate"));

        PKCS12SafeBagBuilder eeCertBagBuilder = new JcaPKCS12SafeBagBuilder(chain[0]);
        eeCertBagBuilder.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName,
                new DERBMPString("User Key"));
        eeCertBagBuilder.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_localKeyId,
                extUtils.createSubjectKeyIdentifier(pubKey));

        char[] passwdChars = passwd.toCharArray();
        PKCS12SafeBagBuilder keyBagBuilder = new JcaPKCS12SafeBagBuilder(priKey,
                new BcPKCS12PBEOutputEncryptorBuilder(
                        PKCSObjectIdentifiers.pbeWithSHAAnd3_KeyTripleDES_CBC,
                        new CBCBlockCipher(new DESedeEngine())).build(passwdChars));
        keyBagBuilder.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName,
                new DERBMPString("User Key"));
        keyBagBuilder.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_localKeyId,
                extUtils.createSubjectKeyIdentifier(pubKey));

        PKCS12PfxPduBuilder pfxPduBuilder = new PKCS12PfxPduBuilder();
        PKCS12SafeBag[] certs = new PKCS12SafeBag[3];
        certs[0] = eeCertBagBuilder.build();
        certs[1] = caCertBagBuilder.build();
        certs[2] = taCertBagBuilder.build();
        pfxPduBuilder.addEncryptedData(new BcPKCS12PBEOutputEncryptorBuilder(
                        PKCSObjectIdentifiers.pbeWithSHAAnd40BitRC2_CBC,
                        new CBCBlockCipher(new RC2Engine())).build(passwdChars),
                certs);
        pfxPduBuilder.addData(keyBagBuilder.build());
        return pfxPduBuilder.build(new BcPKCS12MacCalculatorBuilder(), passwdChars);
    }

    /**
     * @param privKey 用户私钥
     * @param pubKey  用户公钥
     * @param cert    X509证书
     * @param passwd  口令
     * @return
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws PKCSException
     */
    public PKCS12PfxPdu makePfx(PrivateKey privKey, PublicKey pubKey, X509Certificate cert, String passwd)
            throws NoSuchAlgorithmException, IOException, PKCSException {
        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();

        PKCS12SafeBagBuilder eeCertBagBuilder = new JcaPKCS12SafeBagBuilder(cert);
        eeCertBagBuilder.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName,
                new DERBMPString("User Key"));
        eeCertBagBuilder.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_localKeyId,
                extUtils.createSubjectKeyIdentifier(pubKey));

        char[] passwdChars = passwd.toCharArray();
        PKCS12SafeBagBuilder keyBagBuilder = new JcaPKCS12SafeBagBuilder(privKey,
                new BcPKCS12PBEOutputEncryptorBuilder(
                        PKCSObjectIdentifiers.pbeWithSHAAnd3_KeyTripleDES_CBC,
                        new CBCBlockCipher(new DESedeEngine())).build(passwdChars));
        keyBagBuilder.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName,
                new DERBMPString("User Key"));
        keyBagBuilder.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_localKeyId,
                extUtils.createSubjectKeyIdentifier(pubKey));

        PKCS12PfxPduBuilder pfxPduBuilder = new PKCS12PfxPduBuilder();
        PKCS12SafeBag[] certs = new PKCS12SafeBag[1];
        certs[0] = eeCertBagBuilder.build();
        pfxPduBuilder.addEncryptedData(new BcPKCS12PBEOutputEncryptorBuilder(
                        PKCSObjectIdentifiers.pbeWithSHAAnd40BitRC2_CBC,
                        new CBCBlockCipher(new RC2Engine())).build(passwdChars),
                certs);
        pfxPduBuilder.addData(keyBagBuilder.build());
        return pfxPduBuilder.build(new BcPKCS12MacCalculatorBuilder(), passwdChars);
    }


    /**
     * @param sigKey   签名证书私钥
     * @param sigCert  签名证书
     * @param sigAlias 签名证书别名
     * @param encCert  加密证书
     * @param encKey   加密证书私钥
     * @param encAlias 加密证书别名
     * @param ca       上层证书链
     * @param passwd   pfx文件密码，取证书对应私钥密码
     * @return PKCS12PfxPdu
     */
    public PKCS12PfxPdu makePfx(PrivateKey sigKey, X509Certificate sigCert, String sigAlias,
                                X509Certificate encCert, PrivateKey encKey, String encAlias,
                                X509Certificate[] ca, String passwd)
            throws NoSuchAlgorithmException, IOException, PKCSException {

        char[] passwdChars = passwd.toCharArray();
        PKCS12PfxPduBuilder pfxPduBuilder = new PKCS12PfxPduBuilder();
        int size = ca == null ? 0 : ca.length;
        PKCS12SafeBag[] certs = new PKCS12SafeBag[size + 2];
        for (int i = 0; i < size; i++) {
            certs[i] = createPKCS12SafeBag("ca-" + (ca.length - i), ca[i]);
        }

        certs[size] = createPKCS12SafeBag(sigAlias, sigCert);
        certs[size + 1] = createPKCS12SafeBag(encAlias, encCert);


        pfxPduBuilder.addEncryptedData(new BcPKCS12PBEOutputEncryptorBuilder(
                        PKCSObjectIdentifiers.pbeWithSHAAnd40BitRC2_CBC,
                        new CBCBlockCipher(new RC2Engine())).build(passwdChars),
                certs);

        PKCS12SafeBag sigKeyBag = createPKCS12SafeBag(sigAlias, sigCert, sigKey, passwdChars);
        PKCS12SafeBag encKeyBag = createPKCS12SafeBag(encAlias, encCert, encKey, passwdChars);
        pfxPduBuilder.addData(sigKeyBag);
        pfxPduBuilder.addData(encKeyBag);

        return pfxPduBuilder.build(new BcPKCS12MacCalculatorBuilder(), passwdChars);
    }


    private PKCS12SafeBag createPKCS12SafeBag(String alias, X509Certificate cert) throws IOException {
        PKCS12SafeBagBuilder certBagBuilder = new JcaPKCS12SafeBagBuilder(cert);
        certBagBuilder.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName,
                new DERBMPString(alias));
        return certBagBuilder.build();
    }

    private PKCS12SafeBag createPKCS12SafeBag(String alias, X509Certificate cert, PrivateKey privateKey, char[] passwdChars) throws NoSuchAlgorithmException {

        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();

        PKCS12SafeBagBuilder keyBagBuilder = new JcaPKCS12SafeBagBuilder(privateKey,
                new BcPKCS12PBEOutputEncryptorBuilder(
                        PKCSObjectIdentifiers.pbeWithSHAAnd3_KeyTripleDES_CBC,
                        new CBCBlockCipher(new DESedeEngine())).build(passwdChars));
        keyBagBuilder.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName,
                new DERBMPString(alias));
        keyBagBuilder.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_localKeyId,
                extUtils.createSubjectKeyIdentifier(cert.getPublicKey()));

        return keyBagBuilder.build();
    }


}
