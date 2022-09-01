package net.gmkai.crypto;

import net.gmkai.TLSText;
import net.gmkai.crypto.impl.TLSBlockCipherImpl;
import net.gmkai.crypto.padding.Padding;
import net.gmkai.util.ByteBuffers;

import javax.net.ssl.SSLException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;

public class TLSBlockCipher implements TLSCipher {

    private final TLSBlockCipherImpl encryptCipher;

    private final TLSBlockCipherImpl decryptCipher;

    private final Padding padding;

    private final TLSHMac encryptMac;

    private final TLSHMac decryptMac;

    private final int cipherKeySize;

    private final byte[] decryptIv;

    private final byte[] encryptIv;


    public TLSBlockCipher(TLSCryptoParameters cryptoParameters, TLSBlockCipherImpl encryptCipher, TLSBlockCipherImpl decryptCipher,
                          TLSHMac encryptMac, TLSHMac decryptMac, int cipherKeySize, Padding padding) throws IOException {

        encryptCipher.setKey(cryptoParameters.getSelfCryptoKey(), 0, cipherKeySize);
        encryptCipher.init(cryptoParameters.getSelfCryptoIv(), 0, cipherKeySize);
        decryptCipher.setKey(cryptoParameters.getPeerCryptoKey(), 0, cipherKeySize);
        decryptCipher.init(cryptoParameters.getPeerCryptoIv(), 0, cipherKeySize);

        encryptMac.setKey(cryptoParameters.getSelfMacKey(), 0, cryptoParameters.getSelfMacKey().length);
        decryptMac.setKey(cryptoParameters.getPeerMackey(), 0, cryptoParameters.getPeerMackey().length);

        this.encryptCipher = encryptCipher;
        this.decryptCipher = decryptCipher;
        this.encryptMac = encryptMac;
        this.decryptMac = decryptMac;
        this.cipherKeySize = cipherKeySize;
        this.padding = padding;
        this.encryptIv = cryptoParameters.getSelfCryptoIv();
        this.decryptIv = cryptoParameters.getPeerCryptoIv();

    }


    @Override
    public TLSText decryptTLSText(long seqNo, TLSText encryptedText) throws IOException {
        int encryptedFragmentLength = encryptedText.fragment.length;

        byte[] output = new byte[encryptedFragmentLength];
        decryptCipher.doFinal(encryptedText.fragment, 0, encryptedFragmentLength
                , output, 0);

        int plainFragmentLength =
                encryptedFragmentLength - padding.getPaddingCount(output, 0, encryptedFragmentLength)
                        - decryptMac.getMacLength() - cipherKeySize;


        byte[] plainFragment = new byte[plainFragmentLength];
        System.arraycopy(output, cipherKeySize, plainFragment, 0, plainFragmentLength);
        byte[] mac = new byte[decryptMac.getMacLength()];
        System.arraycopy(output, plainFragmentLength + encryptIv.length, mac, 0, mac.length);

        TLSText plaintext = new TLSText(encryptedText.contentType, encryptedText.version, plainFragment);

        verifyMac(seqNo, mac, plaintext);

        return plaintext;
    }

    @Override
    public void updateDecryptKey(byte[] key, int keyOff, int keyLen) throws IOException {
        encryptCipher.setKey(key, keyOff, keyLen);
    }

    @Override
    public TLSText encryptTLSText(long seqNo, TLSText plaintext) throws IOException {

        int dataLength = cipherKeySize + plaintext.fragment.length + encryptMac.getMacLength();
        byte[] paddingBytes = padding.getPaddingBytes(dataLength, encryptCipher.getBlockSize());
        byte[] input = new byte[dataLength + paddingBytes.length];

        ByteBuffer inputByteBuffer = ByteBuffer.wrap(input);

        byte[] macVal = calculateRecordMAC(seqNo, plaintext, encryptMac);
        ByteBuffers.putBytes(inputByteBuffer, encryptIv, plaintext.fragment, macVal, paddingBytes);

        byte[] output = new byte[dataLength + paddingBytes.length];
        encryptCipher.doFinal(input, 0, input.length, output, 0);

        return new TLSText(plaintext.contentType, plaintext.version, output);
    }

    @Override
    public void updateEncryptKey(byte[] key, int keyOff, int keyLen) throws IOException {
        decryptCipher.setKey(key, keyOff, keyLen);
    }


    private byte[] calculateRecordMAC(long seqNo, TLSText plaintext, TLSHMac mac) throws IOException {

        int dataLength = 8 + 1 + 2 + 2 + plaintext.fragment.length;
        byte[] data = new byte[dataLength];
        ByteBuffer buffer = ByteBuffer.wrap(data);
        ByteBuffers.putLong64(buffer, seqNo);
        buffer.put(plaintext.contentType.id);

        ByteBuffers.putInt16(buffer, plaintext.version.getId());
        ByteBuffers.putBytes16(buffer, plaintext.fragment);
        byte[] maxResult = new byte[mac.getMacLength()];

        mac.update(data, 0, dataLength);
        mac.calculateMAC(maxResult, 0);
        return maxResult;

    }

    private void verifyMac(long seqNo, byte[] actualMac, TLSText plaintext) throws IOException {
        byte[] expectedMac = calculateRecordMAC(seqNo, plaintext, decryptMac);

        if (Arrays.equals(actualMac, expectedMac)) return;
        throw new SSLException("mac不一致");
    }
}
