package net.gmkai;

import net.gmkai.util.ByteBufferBuilder;
import net.gmkai.util.ByteBuffers;

import javax.net.ssl.SSLException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

import static net.gmkai.util.BufferWriteOperations.*;

public class TLCP11ProtocolMatcher implements ProtocolMatcher {

    private static final ProtocolVersion protocolVersion = ProtocolVersion.TLCP11;

    @Override
    public HandshakeMsg createClientHello(PreHandshakeContext preHandshakeContext, HandshakeNegotiatorSession handshakeNegotiatorSession) {


        SecureRandom secureRandom = preHandshakeContext.getSecureRandom();

        byte[] clientRandom = secureRandom.generateSeed(32);

        handshakeNegotiatorSession.setClientRandom(clientRandom);

        List<TLSCipherSuite> suites = preHandshakeContext.getSupportTLSCipherSuites();

        List<CompressionMethod> compressionMethods = preHandshakeContext.getSupportCompressionMethods();
        //todo  supported session reuse
        byte[] sessionId = new byte[0];

        return new ClientHelloMsg(protocolVersion, clientRandom, sessionId, suites, compressionMethods);
    }

    @Override
    public HandshakeMsg createServerHello(PreHandshakeContext preHandshakeContext, HandshakeNegotiatorSession handshakeNegotiatorSession) {


        SecureRandom secureRandom = preHandshakeContext.getSecureRandom();

        byte[] serverRandom = secureRandom.generateSeed(32);
        handshakeNegotiatorSession.setServerRandom(serverRandom);

        byte[] sessionId = handshakeNegotiatorSession.getSessionId();

        TLSCipherSuite tlsCipherSuite = handshakeNegotiatorSession.getTlsCipherSuite();

        CompressionMethod compressionMethod = handshakeNegotiatorSession.getCompressionMethod();

        return new ServerHelloMsg(protocolVersion, serverRandom, sessionId, tlsCipherSuite, compressionMethod);
    }

    @Override
    public boolean consumeClientHello(byte[] clientHello, PreHandshakeContext preHandshakeContext, HandshakeNegotiatorSession handshakeNegotiatorSession) {
        try {

            ClientHelloMsg clientHelloMsg = new ClientHelloMsg(ByteBuffer.wrap(clientHello));

            verifyProtocolVersion(clientHelloMsg.version);

            TLSCipherSuite tlsCipherSuite = chooseTLSCipherSuite(preHandshakeContext, clientHelloMsg.suites);

            CompressionMethod compressionMethod = chooseCompressionMethod(clientHelloMsg.compressionMethods);

            byte[] sessionId = chooseSessionId(preHandshakeContext, clientHelloMsg.sessionId);

            handshakeNegotiatorSession.setSessionId(sessionId);
            handshakeNegotiatorSession.setProtocolVersion(clientHelloMsg.version);
            handshakeNegotiatorSession.setClientRandom(clientHelloMsg.random);
            handshakeNegotiatorSession.setTlsCipherSuite(tlsCipherSuite);
            handshakeNegotiatorSession.setCompressionMethod(compressionMethod);
            handshakeNegotiatorSession.setProtocolVersion(ProtocolVersion.TLCP11);

            if (sessionId == clientHelloMsg.sessionId) {
                handshakeNegotiatorSession.makeReusable();
            }

        } catch (Exception e) {

            return false;
        }
        return true;
    }

    private byte[] chooseSessionId(PreHandshakeContext preHandshakeContext, byte[] sessionId) {
        //todo  supported session reuse

        SecureRandom secureRandom = preHandshakeContext.getSecureRandom();

        return secureRandom.generateSeed(4);
    }

    @Override
    public boolean consumeServerHello(byte[] serverHello, PreHandshakeContext preHandshakeContext, HandshakeNegotiatorSession handshakeNegotiatorSession) {
        try {

            ServerHelloMsg serverHelloMsg = new ServerHelloMsg(ByteBuffer.wrap(serverHello));

            verifyProtocolVersion(serverHelloMsg.serverVersion);

            if (handshakeNegotiatorSession.getSessionId() == preHandshakeContext.getReusableSessionId()) {
                handshakeNegotiatorSession.makeReusable();
            }

            handshakeNegotiatorSession.setServerRandom(serverHelloMsg.serverRandom);
            handshakeNegotiatorSession.setSessionId(serverHelloMsg.sessionId);

            if (!preHandshakeContext.getSupportCompressionMethods().contains(serverHelloMsg.compressionMethod)) {
                throw new SSLException("not support compress method");
            }

            handshakeNegotiatorSession.setCompressionMethod(serverHelloMsg.compressionMethod);

            if (!preHandshakeContext.getSupportTLSCipherSuites().contains(serverHelloMsg.tlsCipherSuite)) {
                throw new SSLException("not support compress cipher suite");
            }

            handshakeNegotiatorSession.setTlsCipherSuite(serverHelloMsg.tlsCipherSuite);
            handshakeNegotiatorSession.setProtocolVersion(ProtocolVersion.TLCP11);
        } catch (Exception e) {
            return false;
        }

        return true;
    }

    void verifyProtocolVersion(ProtocolVersion actualProtocolVersion) throws SSLException {
        if (protocolVersion != actualProtocolVersion) {
            throw new SSLException("not support this protocol version");
        }
    }

    private TLSCipherSuite chooseTLSCipherSuite(PreHandshakeContext preHandshakeContext,
                                                List<TLSCipherSuite> tlsCipherSuites) throws SSLException {

        List<TLSCipherSuite> supportedTLSCipherSuite = preHandshakeContext.getSupportTLSCipherSuites();

        return tlsCipherSuites.stream().filter(supportedTLSCipherSuite::contains).
                findFirst().
                orElseThrow(() -> new SSLException("dont have supported cipher suite"));

    }

    private CompressionMethod chooseCompressionMethod(List<CompressionMethod> compressionMethods) throws SSLException {
        if (compressionMethods.contains(CompressionMethod.NULL)) {
            return CompressionMethod.NULL;
        }
        throw new SSLException("dont have supported compress method");
    }

    private static class ClientHelloMsg extends HandshakeMsg {

        private ProtocolVersion version;

        private byte[] random;

        private byte[] sessionId;

        private List<TLSCipherSuite> suites;

        private List<CompressionMethod> compressionMethods;

        ClientHelloMsg(ProtocolVersion version, byte[] random,
                       byte[] sessionId, List<TLSCipherSuite> cipherSuites, List<CompressionMethod> compressionMethods) {

            this.version = version;
            this.sessionId = sessionId;
            this.suites = cipherSuites;
            this.random = random;
            this.compressionMethods = compressionMethods;

        }

        ClientHelloMsg(ByteBuffer m) throws IOException {
            super(m);
        }

        @Override
        HandshakeType getHandshakeType() {
            return HandshakeType.CLIENT_HELLO;
        }

        @Override
        byte[] getMsgBytes() throws IOException {
            ByteBufferBuilder builder = ByteBufferBuilder.
                    bufferCapacity(messageLength()).
                    operate(putInt16(version.id)).
                    operate(putBytes(random)).
                    operate(putBytes8(sessionId)).
                    operate(putInt16(suites.size() * 2));

            suites.forEach(suite -> builder.operate(putInt16(suite.id)));

            builder.operate(putInt8(compressionMethods.size()));

            compressionMethods.forEach(compressionMethod -> builder.operate(putInt8(compressionMethod.getId())));

            return builder.buildByteArray();
        }

        @Override
        int messageLength() {
            return 2 + random.length + 1 + sessionId.length + 2 + suites.size() * 2
                    + 1 + compressionMethods.size();
        }

        @Override
        void parse(ByteBuffer buffer) throws IOException {

            parseVersion(buffer);

            parseRandom(buffer);

            parseSessionId(buffer);

            parseTLSCipherSuites(buffer);

            parseCompressionMethods(buffer);


        }

        private void parseTLSCipherSuites(ByteBuffer buffer) throws IOException {
            byte[] encodedIds = ByteBuffers.getBytes16(buffer);

            if (encodedIds.length == 0 || (encodedIds.length & 0x01) != 0) {
                throw new SSLException("Invalid ClientHello message");
            }
            this.suites = new LinkedList<>();

            for (int i = 0; i < encodedIds.length; i++) {
                TLSCipherSuite.valueOf(((encodedIds[i++] & 0xFF) << 8) | (encodedIds[i] & 0xFF)).
                        ifPresent(cs -> suites.add(cs));
            }

        }

        private void parseCompressionMethods(ByteBuffer buffer) throws IOException {
            byte[] encodedIds = ByteBuffers.getBytes8(buffer);

            if (encodedIds.length == 0) {
                throw new SSLException("Invalid ClientHello message");
            }

            this.compressionMethods = new ArrayList<>();

            for (byte encodedId : encodedIds) {
                CompressionMethod.valueOf(encodedId).
                        ifPresent(compressionMethod -> compressionMethods.add(compressionMethod));
            }
        }

        private void parseRandom(ByteBuffer buffer) {
            this.random = new byte[32];
            buffer.get(random);
        }

        private void parseVersion(ByteBuffer buffer) throws IOException {
            int id = ByteBuffers.getInt16(buffer);
            this.version = ProtocolVersion.valueOf(id).
                    orElseThrow(() -> new SSLException("failed to parse Protocol Version"));
        }

        private void parseSessionId(ByteBuffer buffer) throws IOException {
            this.sessionId = ByteBuffers.getBytes8(buffer);
        }
    }


    private static class ServerHelloMsg extends HandshakeMsg {

        private ProtocolVersion serverVersion;

        private byte[] serverRandom; //32bit

        private byte[] sessionId;

        private TLSCipherSuite tlsCipherSuite;

        private CompressionMethod compressionMethod;

        ServerHelloMsg(ProtocolVersion serverVersion,
                       byte[] serverRandom, byte[] sessionId, TLSCipherSuite tlsCipherSuite, CompressionMethod compressionMethod) {
            this.serverVersion = serverVersion;
            this.serverRandom = serverRandom;
            this.sessionId = sessionId;
            this.tlsCipherSuite = tlsCipherSuite;
            this.compressionMethod = compressionMethod;

        }

        ServerHelloMsg(ByteBuffer buffer) throws IOException {
            super(buffer);
        }

        @Override
        HandshakeType getHandshakeType() {
            return HandshakeType.SERVER_HELLO;
        }

        @Override
        byte[] getMsgBytes() throws IOException {

            return ByteBufferBuilder.bufferCapacity(messageLength()).
                    operate(putInt16(serverVersion.id)).
                    operate(putBytes(serverRandom)).
                    operate(putBytes8(sessionId)).
                    operate(putInt16(tlsCipherSuite.id)).
                    operate(putInt8(compressionMethod.id)).buildByteArray();
        }

        @Override
        int messageLength() {
            return 2 + 32 + 1 + sessionId.length + 2 + 1;
        }

        @Override
        void parse(ByteBuffer buffer) throws IOException {
            serverVersion = ProtocolVersion.valueOf(
                    ByteBuffers.getInt16(buffer)).
                    orElseThrow(() -> new SSLException("failed to parse protocol version"));

            serverRandom = new byte[32];
            buffer.get(serverRandom);
            sessionId = ByteBuffers.getBytes8(buffer);

            tlsCipherSuite = TLSCipherSuite.valueOf(
                    ByteBuffers.getInt16(buffer)).orElseThrow(() -> new SSLException("failed to parse cipher suite"));

            compressionMethod = CompressionMethod.valueOf(buffer.get()).orElseThrow(() -> new SSLException("failed to parse cipher compression method"));
        }
    }


}