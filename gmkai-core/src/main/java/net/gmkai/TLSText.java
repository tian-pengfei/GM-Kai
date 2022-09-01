package net.gmkai;


public class TLSText {

    final public ContentType contentType;

    final public ProtocolVersion version;

    final public byte[] fragment;

    public TLSText(ContentType contentType, ProtocolVersion version, byte[] fragment) {
        this.contentType = contentType;
        this.version = version;
        this.fragment = fragment;
    }
}
