package com.tianpengfei.gmkai.handshake;


import com.google.common.collect.Lists;
import com.tianpengfei.gmkai.CipherSuite;
import com.tianpengfei.gmkai.GMSSLSession;
import com.tianpengfei.gmkai.ProtocolVersion;
import com.tianpengfei.gmkai.util.ByteBuffers;
import org.bouncycastle.util.encoders.Hex;

import javax.net.ssl.SSLException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

public class ClientHello {

    static final HandshakeProducer handshakeProducer = null;

    static final HandshakeConsumer handshakeConsumer = null;


    static final class ClientRandom {
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
        public String toString() {
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


    static final class ClientHelloMessage extends HandshakeMessage {

        private final ProtocolVersion version;
        private final byte[] random;
        private final byte[] sessionId;
        private final List<CipherSuite> suites;
        private final List<CompressionMethod> compressionMethods;


        private HandshakeContext handshakeContext;

        ClientHelloMessage(HandshakeContext handshakeContext, ProtocolVersion version, byte[] random,
                           byte[] sessionId, List<CipherSuite> cipherSuites) {

            this.handshakeContext = handshakeContext;
            this.version = version;
            this.compressionMethods = Lists.newArrayList(CompressionMethod.NULL);
            this.sessionId = sessionId;
            this.suites = cipherSuites;
            this.random = random;

        }

        public ClientHelloMessage(HandshakeContext handshakeContext, ByteBuffer message) throws IOException {

            this.version = ProtocolVersion.valueOf(((message.get() & 0xFF) << 8) | (message.get() & 0xFF));
            if (this.version == null) {
                throw new SSLException("");
            }
            this.random = new byte[32];
            message.get(random);

            this.sessionId = ByteBuffers.getBytes8(message);


            byte[] encodedIds = ByteBuffers.getBytes16(message);
            if (encodedIds.length == 0 || (encodedIds.length & 0x01) != 0) {
                throw new SSLException("Invalid ClientHello message");
            }
            this.suites = new LinkedList<>();
            for (int i = 0; i < encodedIds.length; i++) {
                CipherSuite suite = CipherSuite.valueOf(((encodedIds[i++] & 0xFF) << 8) | (encodedIds[i] & 0xFF));
                if (suite != null) {
                    suites.add(suite);
                }
            }

            encodedIds = ByteBuffers.getBytes8(message);
            if (encodedIds.length == 0) {
                throw new SSLException("Invalid ClientHello message");
            }

            this.compressionMethods = new ArrayList<>();
            for (byte encodedId : encodedIds) {
                CompressionMethod compressionMethod
                        = CompressionMethod.getInstance(encodedId);
                if (compressionMethod != null) {
                    this.compressionMethods.add(compressionMethod);
                }
            }

        }

        private static List<CipherSuite> getCipherSuites(int[] ids) {
            List<CipherSuite> cipherSuites = new LinkedList<>();
            for (int id : ids) {
                CipherSuite cipherSuite = CipherSuite.valueOf(id);
                if (cipherSuite != null) {
                    cipherSuites.add(cipherSuite);
                }
            }

            return Collections.unmodifiableList(cipherSuites);
        }


        @Override
        byte[] getHandshakeType() {
            return new byte[0];
        }

        @Override
        byte[] getBytes() throws IOException {

            byte[] message = new byte[messageLength()];
            ByteBuffer m = ByteBuffer.wrap(message);

            ByteBuffers.putInt16(m, version.getId());

            m.put(random);

            ByteBuffers.putBytes8(m, sessionId);

            ByteBuffers.putInt16(m, suites.size() * 2);
            for (CipherSuite suite : suites) {
                ByteBuffers.putInt16(m, suite.getId());
            }

            ByteBuffers.putInt8(m, compressionMethods.size());
            for (CompressionMethod method : compressionMethods) {
                ByteBuffers.putInt8(m, method.getValue());
            }

            return message;
        }

        @Override
        void parse(byte[] messages) {

        }

        @Override
        int messageLength() {

            return 2 + random.length + 1 + sessionId.length + 2 + suites.size() * 2
                    + 1 + compressionMethods.size();
        }
    }


    private static final class ClientHelloConsumer implements HandshakeConsumer {


        @Override
        public void consume(HandshakeContext handshakeContext, ByteBuffer message) throws IOException {

            ClientHelloMessage clientHello = new ClientHelloMessage(handshakeContext, message);

            handshakeContext.negotiatedProtocol = negotiateProtocol(handshakeContext, clientHello.version);

            if (clientHello.sessionId.length != 0) {
                //复用session

            } else {
                handshakeContext.handshakeSession = new GMSSLSession();
            }

            handshakeContext.clientRandom = clientHello.random;

            handshakeContext.negotiatedCipherSuite = negotiateCipherSuite(handshakeContext, clientHello.suites);

            //触发事件机制推动握手进程。


        }

        private CipherSuite negotiateCipherSuite(HandshakeContext hc, List<CipherSuite> suites) throws SSLException {
            return suites.stream().filter(hc.activeCipherSuites::contains).findFirst()
                    .orElseThrow(() -> new SSLException("没有支持的套件"));
        }

        private ProtocolVersion negotiateProtocol(
                HandshakeContext context,
                ProtocolVersion clientSupportedVersion) throws SSLException {

            //只支持国密1.1

            if (clientSupportedVersion.getId() == ProtocolVersion.GMSSL11.getId()) {
                return clientSupportedVersion;
            }
            throw new SSLException("不支持此协议版本");
        }
    }

    private static final class ClientHelloProducer implements HandshakeProducer {

        @Override
        public HandshakeMessage produce(HandshakeContext handshakeContext) {

            return null;
        }
    }

}
