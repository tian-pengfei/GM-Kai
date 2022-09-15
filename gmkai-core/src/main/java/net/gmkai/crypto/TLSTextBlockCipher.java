package net.gmkai.crypto;

import net.gmkai.SequenceNumber;
import net.gmkai.TLSText;
import net.gmkai.crypto.impl.TLSBlockCipher;
import net.gmkai.crypto.padding.Padding;
import net.gmkai.util.ByteBufferBuilder;

import javax.net.ssl.SSLException;
import java.io.IOException;
import java.util.Arrays;

import static net.gmkai.util.BufferWriteOperations.*;

public class TLSTextBlockCipher implements TLSTextCipher {

    private final TLSBlockCipher tlsBlockCipher;

    private final Padding padding;

    private final TLSHMac tlshMac;

    private final int cipherKeySize;

    private final byte[] cryptoIv;

    boolean forEncryption;

    private final SequenceNumber sequenceNumber = new SequenceNumber();

    public TLSTextBlockCipher(boolean forEncryption, TLSTextCryptoParameters tlsTextCryptoParameters, TLSBlockCipher tlsBlockCipher,
                              TLSHMac tlshMac, int cipherKeySize, Padding padding) throws IOException {

        tlsBlockCipher.setKey(tlsTextCryptoParameters.getCryptoKey(), 0, cipherKeySize);
        tlsBlockCipher.init(tlsTextCryptoParameters.getCryptoKeyIv(), 0, cipherKeySize);


        tlshMac.setKey(tlsTextCryptoParameters.getMacKey(), 0, tlsTextCryptoParameters.getMacKey().length);

        this.tlsBlockCipher = tlsBlockCipher;
        this.tlshMac = tlshMac;
        this.cipherKeySize = cipherKeySize;
        this.padding = padding;
        this.cryptoIv = tlsTextCryptoParameters.getCryptoKeyIv();
        this.forEncryption = forEncryption;

    }


    private TLSText decryptTLSText(long seqNo, TLSText encryptedText) throws IOException {
        int encryptedFragmentLength = encryptedText.fragment.length;

        byte[] output = new byte[encryptedFragmentLength];
        tlsBlockCipher.doFinal(encryptedText.fragment, 0, encryptedFragmentLength
                , output, 0);

        int plainFragmentLength =
                encryptedFragmentLength - padding.getPaddingCount(output, 0, encryptedFragmentLength)
                        - tlshMac.getMacLength() - cipherKeySize;


        byte[] plainFragment = new byte[plainFragmentLength];
        System.arraycopy(output, cipherKeySize, plainFragment, 0, plainFragmentLength);
        byte[] mac = new byte[tlshMac.getMacLength()];
        System.arraycopy(output, plainFragmentLength + cryptoIv.length, mac, 0, mac.length);

        TLSText plaintext = new TLSText(encryptedText.contentType, encryptedText.version, plainFragment);

        verifyMac(seqNo, mac, plaintext);

        return plaintext;
    }

    private TLSText encryptTLSText(long seqNo, TLSText plaintext) throws IOException {

        int dataLength = cipherKeySize + plaintext.fragment.length + tlshMac.getMacLength();

        byte[] paddingBytes = padding.getPaddingBytes(dataLength, tlsBlockCipher.getBlockSize());
        byte[] macVal = calculateRecordMAC(seqNo, plaintext, tlshMac);
        int fragmentLength = dataLength + paddingBytes.length;

        byte[] input = ByteBufferBuilder.
                bufferCapacity(fragmentLength).
                operate(putBytes(cryptoIv, plaintext.fragment, macVal, paddingBytes)).buildByteArray();

        byte[] output = new byte[fragmentLength];

        tlsBlockCipher.doFinal(input, 0, input.length, output, 0);

        return new TLSText(plaintext.contentType, plaintext.version, output);
    }


    private byte[] calculateRecordMAC(long seqNo, TLSText plaintext, TLSHMac mac) throws IOException {

        int dataLength = 8 + 1 + 2 + 2 + plaintext.fragment.length;

        byte[] data = ByteBufferBuilder.
                bufferCapacity(dataLength).
                operate(putLong64(seqNo)).
                operate(put(plaintext.contentType.id)).
                operate(putInt16(plaintext.version.getId())).
                operate(putBytes16(plaintext.fragment)).buildByteArray();

        byte[] maxResult = new byte[mac.getMacLength()];

        mac.update(data, 0, dataLength);
        mac.calculateMAC(maxResult, 0);
        return maxResult;

    }

    private void verifyMac(long seqNo, byte[] actualMac, TLSText plaintext) throws IOException {
        byte[] expectedMac = calculateRecordMAC(seqNo, plaintext, tlshMac);

        if (Arrays.equals(actualMac, expectedMac)) return;
        throw new SSLException("mac不一致");
    }

    @Override
    public TLSText processTLSText(TLSText tlsText) throws IOException {
        long seqNo = sequenceNumber.nextValue();

        if (forEncryption) {
            return encryptTLSText(seqNo, tlsText);
        }
        return decryptTLSText(seqNo, tlsText);
    }
}
