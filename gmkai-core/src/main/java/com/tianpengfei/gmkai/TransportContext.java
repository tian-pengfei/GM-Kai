package com.tianpengfei.gmkai;

import com.tianpengfei.gmkai.application.AppInputStream;
import com.tianpengfei.gmkai.application.AppOutputStream;
import com.tianpengfei.gmkai.handshake.HandshakeContext;
import com.tianpengfei.gmkai.record.ContentType;
import com.tianpengfei.gmkai.record.Plaintext;
import com.tianpengfei.gmkai.record.Record;
import com.tianpengfei.gmkai.record.SecurityParameters;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;

public class TransportContext implements ConnectionContext, ConnectSetting {

    boolean isNegotiated = false;

    HandshakeContext handshakeContext;

    private final int peerPort;

    private final String peerHost;

    GMSSLSession connectSession;

    GMSSLSession sslSession;

    //记录层协议
    Record record;

    //应用层协议
    AppInputStream appInputStream;

    AppOutputStream appOutPutStream;

    GMSSLParameters sslParameters;

    TransportContext(GMSSLParameters sslParameters, ConnectSetting connectSetting, InputStream inputStream, OutputStream outputStream) {

        peerHost = connectSetting.getPeerHost();
        peerPort = connectSetting.getPeerPort();

        record = new Record(inputStream, outputStream);
        this.sslParameters = sslParameters;

        handshakeContext = new HandshakeContext(this, sslParameters);
    }

    public void startHandshake() throws IOException {
        if (!isNegotiated) {
            handshakeContext.startHandshake(this);
        }
    }

    GMSSLSession getSession() {
        try {
            startHandshake();
        } catch (IOException e) {
            return new GMSSLSession();
        }
        if (isNegotiated) {
            connectSession = handshakeContext.getHandshakeSession();
        } else {
            connectSession = new GMSSLSession();
        }
        return connectSession;
    }

    GMSSLSession getHandshakeSession() {
        return handshakeContext.getHandshakeSession();
    }

    InputStream getAppInputStream() {
        if (appInputStream == null) {
            appInputStream = new AppInputStream(this);
        }
        return appInputStream;
    }

    OutputStream getAppOutPutStream() {
        if (appOutPutStream == null) {
            appOutPutStream = new AppOutputStream(this);
        }
        return appOutPutStream;
    }

    public Plaintext readHandshakeRecord() throws IOException {
        Plaintext plaintext = record.read();
        //在接收消息时，接收到其他类型的，怎么处理？
        while (plaintext.getContentType() == ContentType.CHANGE_CIPHER_SPEC) {

            ChangeCipherSpec.consumer.consume(this, ByteBuffer.wrap(
                    plaintext.fragment));
            plaintext = record.read();
        }
        return plaintext;
    }


    public void writeApplicationRecord(byte[] message, int off, int len) throws IOException {

        ByteBuffer _message = ByteBuffer.wrap(message, off, len);

        record.write(ContentType.APPLICATION_DATA, ProtocolVersion.GMSSL11, _message);
    }

    public ByteBuffer readApplicationRecord(
            ByteBuffer buffer) throws IOException {

        while (true) {
            Plaintext plaintext = record.read();
            if (plaintext.getContentType() == ContentType.APPLICATION_DATA) {
                if (buffer.remaining() < plaintext.fragment.length) {
                    buffer = ByteBuffer.allocate(plaintext.fragment.length);
                }

                buffer.put(plaintext.fragment);

                return buffer;
            } else {

            }
        }

    }

    public boolean isNegotiated() {
        return isNegotiated;
    }

    public void setNegotiated(boolean negotiated) {
        isNegotiated = negotiated;
    }

    @Override
    public int getPeerPort() {
        return peerPort;
    }

    @Override
    public String getPeerHost() {
        return peerHost;
    }


    public void writeHandshakeRecord(ByteBuffer buffer) throws IOException {

        record.writeHandshake(buffer);

    }

    public void sendChangeCipherSpec() throws IOException {
        byte[] m = ChangeCipherSpec.producer.produce(this);
        record.writeChangeCipherSpec(ByteBuffer.wrap(m));
        ChangeCipherSpec.producer.finish(this);
    }

    public void updateSecurityParameters() throws IOException {
        SecurityParameters securityParameters = handshakeContext.getSecurityParams();
        record.updateSecurityParameters(securityParameters);
    }

    public void updateWriteKey() {
        record.updateWriteKey();
    }

    public void updateReadKey() {
        record.updateReadKey();
    }


    public void closeRead() throws IOException {
        record.closeRead();
    }

    public void closeWrite() throws IOException {
        record.closeWrite();
    }
}
