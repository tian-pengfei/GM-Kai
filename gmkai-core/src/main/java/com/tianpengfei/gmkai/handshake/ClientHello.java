package com.tianpengfei.gmkai.handshake;


import com.google.common.collect.Lists;
import com.tianpengfei.gmkai.CipherSuite;
import com.tianpengfei.gmkai.CompressionMethod;
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
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

public class ClientHello {

    static final HandshakeProducer handshakeProducer = new ClientHelloProducer();

    static final HandshakeConsumer handshakeConsumer = new ClientHelloConsumer();


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


    static final class ClientHelloMessage extends HandshakeMessage {

        private final ProtocolVersion version;
        private final byte[] random;
        private final byte[] sessionId;
        private final List<CipherSuite> suites;
        private final List<CompressionMethod> compressionMethods;


        ClientHelloMessage(ProtocolVersion version, byte[] random,
                           byte[] sessionId, List<CipherSuite> cipherSuites) {

            this.version = version;
            this.compressionMethods = Lists.newArrayList(CompressionMethod.NULL);
            this.sessionId = sessionId;
            this.suites = cipherSuites;
            this.random = random;

        }

        public ClientHelloMessage(ByteBuffer m) throws IOException {

            this.version = ProtocolVersion.valueOf(ByteBuffers.getInt16(m));
            if (this.version == null) {
                throw new SSLException("");
            }
            this.random = new byte[32];
            m.get(random);

            this.sessionId = ByteBuffers.getBytes8(m);


            byte[] encodedIds = ByteBuffers.getBytes16(m);
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

            encodedIds = ByteBuffers.getBytes8(m);
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
        public SSLHandshakeType getHandshakeType() {
            return SSLHandshakeType.CLIENT_HELLO;
        }

        @Override
        public byte[] getBytes() throws IOException {

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
        int messageLength() {

            return 2 + random.length + 1 + sessionId.length + 2 + suites.size() * 2
                    + 1 + compressionMethods.size();
        }
    }


    private static final class ClientHelloConsumer implements HandshakeConsumer {


        @Override
        public void consume(HandshakeContext handshakeContext, ByteBuffer message) throws IOException {

            ClientHelloMessage clientHello = new ClientHelloMessage(message);

            handshakeContext.negotiatedProtocol = negotiateProtocol(handshakeContext, clientHello.version);

            if (clientHello.sessionId.length != 0) {
                //复用session

            } else {
                SecureRandom random = new SecureRandom();
                handshakeContext.handshakeSession =
                        new GMSSLSession(handshakeContext.negotiatedProtocol, random.generateSeed(64),
                                handshakeContext.transportContext.getPeerHost(),
                                handshakeContext.transportContext.getPeerPort());
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
                HandshakeContext handshakeContext,
                ProtocolVersion clientSupportedVersion) throws SSLException {

            //只支持国密1.1

            if (clientSupportedVersion.getId() == ProtocolVersion.GMSSL11.getId()) {
                return clientSupportedVersion;
            }
            throw new SSLException("不支持此协议版本");
        }

        @Override
        public SSLHandshakeType handshakeType() {

            return SSLHandshakeType.CLIENT_HELLO;
        }
    }

    private static final class ClientHelloProducer implements HandshakeProducer {

        @Override
        public HandshakeMessage produce(HandshakeContext handshakeContext) {

            byte[] clientRandom = new byte[32];
            SecureRandom secureRandom = new SecureRandom();
            secureRandom.nextBytes(clientRandom);

            ClientHelloMessage clientHelloMessage = new ClientHelloMessage(
                    handshakeContext.maxProtocolVersion,
                    clientRandom, new byte[0], handshakeContext.activeCipherSuites
            );

            handshakeContext.clientRandom = clientRandom;
            return clientHelloMessage;
        }
    }

}
