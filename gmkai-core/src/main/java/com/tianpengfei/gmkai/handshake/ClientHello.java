package com.tianpengfei.gmkai.handshake;


import com.google.common.collect.Lists;
import com.tianpengfei.gmkai.*;
import com.tianpengfei.gmkai.util.ByteBuffers;
import org.bouncycastle.util.encoders.Hex;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.ByteBuffer;
import java.util.List;

public class ClientHello {

    static final HandshakeProducer handshakeProducer = null;

    static final HandshakeConsumer handshakeConsumer = null;


    static  final class ClientRandom{
        public int gmtUnixTime;
        public byte[] randomBytes;

      public ClientRandom(int gmtUnixTime, byte[] randomBytes) {
            this.gmtUnixTime = gmtUnixTime;
            this.randomBytes = randomBytes;
        }

        public byte[] getBytes() throws IOException {
            ByteArrayOutputStream ba = new ByteArrayOutputStream();
            ba.write((gmtUnixTime >>> 24) & 0xFF);
            ba.write((gmtUnixTime >>> 16) & 0xFF);
            ba.write((gmtUnixTime >>> 8) & 0xFF);
            ba.write(gmtUnixTime & 0xFF);
            ba.write(randomBytes);
            return ba.toByteArray();
        }

        @Override
        public String toString()
        {
            StringWriter str = new StringWriter();
            PrintWriter out = new PrintWriter(str);
            out.println("struct {");
            out.println("  gmt_unix_time = " + gmtUnixTime + ";");
            out.println("  random_bytes = " + Hex.toHexString(randomBytes) + ";");
            out.println("} Random;");
            return str.toString();
        }
    }

    static final class CompressionMethod {

        private final int value;

        public CompressionMethod(int value) {
            this.value = value;
        }

        public int getValue() {
            return value;
        }

        @Override
        public String toString() {
            switch (value) {
                case 0:
                    return "null";
                case 1:
                    return "zlib";
                default:
                    return "unknown(" + value + ")";
            }
        }

        static final CompressionMethod NULL = new CompressionMethod(0);
        static final CompressionMethod ZLIB = new CompressionMethod(1);

        public static CompressionMethod getInstance(int value) {
            switch (value) {
                case 0:
                    return NULL;
                case 1:
                    return ZLIB;
                default:
                    return new CompressionMethod(value);
            }
        }
    }


    static final class ClientHelloMessage extends HandshakeMessage{

        private final ProtocolVersion version;
        private final byte[] random;
        private final byte[] sessionId;
        private final List<CipherSuite> suites;
        private final List<CompressionMethod> compressionMethods;


        private HandshakeContext handshakeContext;

        ClientHelloMessage(HandshakeContext handshakeContext, ProtocolVersion version,byte[] random,
                           byte[] sessionId, List<CipherSuite> cipherSuites){

            this.handshakeContext = handshakeContext;
            this.version = version;
            this.compressionMethods = Lists.newArrayList(CompressionMethod.NULL);
            this.sessionId = sessionId;
            this.suites = cipherSuites;
            this.random  = random;

        }



        @Override
        byte[] getBytes() throws IOException {

            byte[] message = new byte[messageLength()];
            ByteBuffer m = ByteBuffer.wrap(message);

            ByteBuffers.putInt16(m,version.getId());

            ByteBuffers.putBytes8(m,sessionId);

            ByteBuffers.putInt16(m,suites.size()*2);
            for (CipherSuite suite:suites) {
                ByteBuffers.putInt16(m,suite.getId());
            }

            ByteBuffers.putInt8(m,compressionMethods.size());
            for (CompressionMethod method:compressionMethods) {
                ByteBuffers.putInt8(m,method.getValue());
            }

            return message;
        }

        @Override
        void parse(byte[] messages) {

        }

        @Override
        int messageLength() {

            return 2+random.length+1+sessionId.length+2+suites.size()*2
                    +1+compressionMethods.size();
        }
    }



}
