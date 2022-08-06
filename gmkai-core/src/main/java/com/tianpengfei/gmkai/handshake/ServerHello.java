package com.tianpengfei.gmkai.handshake;

import com.tianpengfei.gmkai.CipherSuite;
import com.tianpengfei.gmkai.CompressionMethod;
import com.tianpengfei.gmkai.GMSSLSession;
import com.tianpengfei.gmkai.ProtocolVersion;
import com.tianpengfei.gmkai.util.ByteBuffers;
import com.tianpengfei.gmkai.util.Bytes;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.SecureRandom;

public class ServerHello {

    static final HandshakeProducer handshakeProducer = new ServerHelloProducer();

    static final HandshakeConsumer handshakeConsumer = new ServerHelloConsumer();

    static final SSLHandshakeType type = SSLHandshakeType.SERVER_HELLO;


    static class ServerHelloMessage extends HandshakeMessage {

        private final ProtocolVersion serverVersion;

        private final byte[] serverRandom; //32bit

        private final byte[] sessionId;

        private final CipherSuite cipherSuite;

        private final CompressionMethod compressionMethod;

        ServerHelloMessage(ProtocolVersion serverVersion,
                           byte[] serverRandom, byte[] sessionId, CipherSuite cipherSuite) {
            this.serverVersion = serverVersion;
            this.serverRandom = serverRandom;
            this.sessionId = sessionId;
            this.cipherSuite = cipherSuite;
            this.compressionMethod = CompressionMethod.NULL;      // Don't support compression.

        }

        ServerHelloMessage(HandshakeContext context, ByteBuffer m) throws IOException {

            serverVersion = ProtocolVersion.valueOf(
                    ByteBuffers.getInt16(m));

            serverRandom = new byte[32];
            m.get(serverRandom);
            sessionId = ByteBuffers.getBytes8(m);
            cipherSuite = CipherSuite.valueOf(
                    ByteBuffers.getInt16(m));

            compressionMethod = CompressionMethod.getInstance(m.get());

        }

        @Override
        SSLHandshakeType getHandshakeType() {
            return type;
        }

        @Override
        byte[] getBytes() throws IOException {

            ByteBuffer m = ByteBuffer.allocate(messageLength());

            ByteBuffers.putInt8(m, serverVersion.getId());
            m.put(serverRandom);
            ByteBuffers.putBytes8(m, sessionId);
            ByteBuffers.putInt16(m, cipherSuite.getId());
            ByteBuffers.putInt8(m, compressionMethod.getValue());

            return m.array();
        }

        @Override
        int messageLength() {
            return 2 + 32 + 1 + sessionId.length + 2 + 1;
        }
    }


    static class ServerHelloProducer implements HandshakeProducer {

        @Override
        public HandshakeMessage produce(HandshakeContext handshakeContext) {

            SecureRandom secureRandom = new SecureRandom();

            byte[] serverRandom = new byte[32];
            secureRandom.nextBytes(serverRandom);

            ServerHelloMessage serverHelloMessage =
                    new ServerHelloMessage(handshakeContext.negotiatedProtocol,
                            serverRandom, secureRandom.generateSeed(2), handshakeContext.negotiatedCipherSuite);

            handshakeContext.serverRandom = serverHelloMessage.serverRandom;
            return serverHelloMessage;
        }
    }

    static class ServerHelloConsumer implements HandshakeConsumer {

        @Override
        public void consume(HandshakeContext handshakeContext, ByteBuffer message) throws IOException {

            ServerHelloMessage serverHelloMessage = new ServerHelloMessage(handshakeContext, message);

            handshakeContext.serverRandom = serverHelloMessage.serverRandom;

            handshakeContext.negotiatedProtocol = serverHelloMessage.serverVersion;

            handshakeContext.negotiatedCipherSuite = serverHelloMessage.cipherSuite;

            handshakeContext.handshakeSession = new GMSSLSession(serverHelloMessage.serverVersion,
                    serverHelloMessage.sessionId, handshakeContext.transportContext.getPeerHost(),
                    handshakeContext.transportContext.getPeerPort());

            handshakeContext.handshakeSession.setCipherSuite(serverHelloMessage.cipherSuite);

        }

        @Override
        public SSLHandshakeType handshakeType() {
            return SSLHandshakeType.SERVER_HELLO;
        }
    }


}
