package com.tianpengfei.gmkai.record;

import com.tianpengfei.gmkai.ProtocolVersion;
import org.bouncycastle.util.encoders.Hex;

public class Plaintext {


    ContentType contentType;

    ProtocolVersion version;

    public byte[] fragment;

    public Plaintext(ContentType contentType, ProtocolVersion version, byte[] fragment) {
        this.contentType = contentType;
        this.version = version;
        this.fragment = fragment;
    }

    public ContentType getContentType() {
        return contentType;
    }

    public void setContentType(ContentType contentType) {
        this.contentType = contentType;
    }

    public ProtocolVersion getVersion() {
        return version;
    }

    public void setVersion(ProtocolVersion version) {
        this.version = version;
    }

    public byte[] getFragment() {
        return fragment;
    }

    public void setFragment(byte[] fragment) {
        this.fragment = fragment;
    }

    public String toString() {
        return String.format("{contentType:%s,\n" +
                "ProtocolVersion:%s,\n" +
                "fragment:%s}", contentType, version, Hex.toHexString(fragment));

    }
}
