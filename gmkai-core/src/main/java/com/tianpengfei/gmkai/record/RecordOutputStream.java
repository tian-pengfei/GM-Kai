package com.tianpengfei.gmkai.record;

import com.tianpengfei.gmkai.ProtocolVersion;

import java.io.OutputStream;
import java.nio.ByteBuffer;

public class RecordOutputStream {


    OutputStream outputStream;


    public void writeAlert(ByteBuffer src) {

    }


    public void writeHandshake(ByteBuffer src) {

    }


    public void writeChangeCipherSpec(ByteBuffer src) {

    }


    public void writeApplication(ByteBuffer src) {

    }

    public void write(
            ContentType contentType, ProtocolVersion version, ByteBuffer src) {

    }

}
