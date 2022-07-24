package com.tianpengfei.gmkai.record;

import com.tianpengfei.gmkai.ProtocolVersion;

public class Plaintext {

    ContentType contentType;

    ProtocolVersion version;

    public byte[] fragment;

    public Plaintext(ContentType contentType, ProtocolVersion version, byte[] fragment) {
        this.contentType = contentType;
        this.version = version;
        this.fragment = fragment;
    }
}
