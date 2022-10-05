package net.gmkai.crypto.impl.bc;

import net.gmkai.crypto.TLSSM2Cipher;
import org.bouncycastle.asn1.*;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;

import javax.net.ssl.SSLException;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;

//todo Configurable mode and encoding
public class BcTLSSM2Cipher extends TLSSM2Cipher {

    private final SM2Engine sm2Engine;

    private final SM2Der sm2Der = new SM2Der();

    private final SM2Engine.Mode mode = SM2Engine.Mode.C1C3C2;

    private final boolean forEncryption;

    public BcTLSSM2Cipher(boolean forEncryption, Key key, SecureRandom secureRandom) throws SSLException {
        sm2Engine = new SM2Engine(mode);
        AsymmetricKeyParameter keyParameter = generateKeyParameters(key);
        this.forEncryption = forEncryption;
        CipherParameters parameters = forEncryption ? new ParametersWithRandom(keyParameter, secureRandom) : keyParameter;
        sm2Engine.init(forEncryption, parameters);
    }

    public BcTLSSM2Cipher(boolean forEncryption, Key key) throws SSLException {
        this(forEncryption, key, new SecureRandom());
    }

    @Override
    public byte[] processBlock(byte[] in, int inOff, int len) throws IOException {
        try {

            if (forEncryption) {
                return sm2Der.encode(sm2Engine.processBlock(in, inOff, len));
            }

            byte[] in2 = new byte[len];
            System.arraycopy(in, inOff, in2, 0, len);
            byte[] _in = sm2Der.decode(in2);
            return sm2Engine.processBlock(_in, 0, _in.length);
        } catch (Exception e) {
            throw new SSLException(e.getMessage(), e);
        }
    }

    private AsymmetricKeyParameter generateKeyParameters(Key key) throws SSLException {
        try {
            if (key instanceof PrivateKey) {
                return ECUtil.generatePrivateKeyParameter((PrivateKey) key);
            }
            return ECUtil.generatePublicKeyParameter((PublicKey) key);
        } catch (InvalidKeyException e) {
            throw new SSLException(e.getMessage(), e);
        }
    }


    private class SM2Der {

        private final int curveLength = 32;

        private int digestLength = 32;

        public byte[] decode(byte[] derCipher) throws Exception {
            ASN1Sequence as = DERSequence.getInstance(derCipher);
            byte[] c1x = ((ASN1Integer) as.getObjectAt(0)).getValue().toByteArray();
            byte[] c1y = ((ASN1Integer) as.getObjectAt(1)).getValue().toByteArray();

            c1x = fixToCurveLengthBytes(c1x);
            c1y = fixToCurveLengthBytes(c1y);
            byte[] c3;
            byte[] c2;
            if (mode == SM2Engine.Mode.C1C2C3) {
                c2 = ((DEROctetString) as.getObjectAt(2)).getOctets();
                c3 = ((DEROctetString) as.getObjectAt(3)).getOctets();
            } else if (mode == SM2Engine.Mode.C1C3C2) {
                c3 = ((DEROctetString) as.getObjectAt(2)).getOctets();
                c2 = ((DEROctetString) as.getObjectAt(3)).getOctets();
            } else {
                throw new Exception("Unsupported mode:" + mode);
            }

            int pos = 0;
            byte[] cipherText = new byte[1 + c1x.length + c1y.length + c2.length + c3.length];
            final byte uncompressedFlag = 0x04;
            cipherText[0] = uncompressedFlag;
            pos += 1;
            System.arraycopy(c1x, 0, cipherText, pos, c1x.length);
            pos += c1x.length;
            System.arraycopy(c1y, 0, cipherText, pos, c1y.length);
            pos += c1y.length;
            if (mode == SM2Engine.Mode.C1C2C3) {
                System.arraycopy(c2, 0, cipherText, pos, c2.length);
                pos += c2.length;
                System.arraycopy(c3, 0, cipherText, pos, c3.length);
            } else if (mode == SM2Engine.Mode.C1C3C2) {
                System.arraycopy(c3, 0, cipherText, pos, c3.length);
                pos += c3.length;
                System.arraycopy(c2, 0, cipherText, pos, c2.length);
            }
            return cipherText;
        }


        public byte[] encode(byte[] cipher) throws IOException {

            byte[] c1x = new byte[curveLength];
            byte[] c1y = new byte[curveLength];
            byte[] c2 = new byte[cipher.length - c1x.length - c1y.length - 1 - digestLength];
            byte[] c3 = new byte[digestLength];

            int startPos = 1;
            System.arraycopy(cipher, startPos, c1x, 0, c1x.length);
            startPos += c1x.length;
            System.arraycopy(cipher, startPos, c1y, 0, c1y.length);
            startPos += c1y.length;
            if (mode == SM2Engine.Mode.C1C2C3) {
                System.arraycopy(cipher, startPos, c2, 0, c2.length);
                startPos += c2.length;
                System.arraycopy(cipher, startPos, c3, 0, c3.length);
            } else if (mode == SM2Engine.Mode.C1C3C2) {
                System.arraycopy(cipher, startPos, c3, 0, c3.length);
                startPos += c3.length;
                System.arraycopy(cipher, startPos, c2, 0, c2.length);
            } else {
                throw new SSLException("Unsupported mode:" + mode);
            }

            ASN1Encodable[] arr = new ASN1Encodable[4];

            arr[0] = new ASN1Integer(new BigInteger(1, c1x));
            arr[1] = new ASN1Integer(new BigInteger(1, c1y));
            if (mode == SM2Engine.Mode.C1C2C3) {
                arr[2] = new DEROctetString(c2);
                arr[3] = new DEROctetString(c3);
            } else if (mode == SM2Engine.Mode.C1C3C2) {
                arr[2] = new DEROctetString(c3);
                arr[3] = new DEROctetString(c2);
            }
            DERSequence ds = new DERSequence(arr);
            return ds.getEncoded(ASN1Encoding.DER);
        }

        private byte[] fixToCurveLengthBytes(byte[] src) {
            if (src.length == curveLength) {
                return src;
            }

            byte[] result = new byte[curveLength];
            if (src.length > curveLength) {
                System.arraycopy(src, src.length - result.length, result, 0, result.length);
            } else {
                System.arraycopy(src, 0, result, result.length - src.length, src.length);
            }
            return result;
        }

    }
}
