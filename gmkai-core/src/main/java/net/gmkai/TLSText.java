package net.gmkai;


import net.gmkai.util.ByteBufferBuilder;

import javax.net.ssl.SSLException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.Objects;

import static net.gmkai.util.BufferWriteOperations.*;
import static net.gmkai.util.Bytes.safeRead;

public class TLSText {

    final public ContentType contentType;

    final public ProtocolVersion version;

    final public byte[] fragment;

    public TLSText(ContentType contentType, ProtocolVersion version, byte[] fragment) {
        this.contentType = contentType;
        this.version = version;
        this.fragment = fragment;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        TLSText tlsText = (TLSText) o;
        return contentType == tlsText.contentType && version == tlsText.version && Arrays.equals(fragment, tlsText.fragment);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(contentType, version);
        result = 31 * result + Arrays.hashCode(fragment);
        return result;
    }

    static TLSText readTLSText(InputStream inputStream) throws IOException {
        int typeInt = inputStream.read();
        if (typeInt == -1) throw new SSLException("inputString 已经结束");

        ContentType contentType = ContentType.valueOf(typeInt).orElseThrow(
                () -> new SSLException("不存在这种类型"));

        ProtocolVersion version = ProtocolVersion.valueOf(
                ((inputStream.read() & 0xFF) << 8) | (inputStream.read() & 0xFF));

        int length = ((inputStream.read() & 0xFF) << 8)
                | (inputStream.read() & 0xFF);

        byte[] fragment = safeRead(inputStream, length);

        return new TLSText(contentType, version, fragment);

    }

    static TLSText readTLSText(byte[] data) throws IOException {
        ByteArrayInputStream inputStream = new ByteArrayInputStream(data);
        return readTLSText(inputStream);
    }

    public byte[] toBytes() throws IOException {

        return ByteBufferBuilder.
                bufferCapacity(1 + 2 + 2 + fragment.length).
                operate(put(contentType.id))
                .operate(putInt16(version.id))
                .operate(putBytes16(fragment)).buildByteArray();
    }
}
