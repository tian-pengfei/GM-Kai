package com.tianpengfei.gmkai.handshake;

import com.tianpengfei.gmkai.cipher.Crypto;

import javax.net.ssl.SSLException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class Finished {

    static SSLHandshakeType TYPE = SSLHandshakeType.FINISHED;

    static final HandshakeProducer handshakeProducer = new FinishedProducer();

    static final HandshakeConsumer handshakeConsumer = new FinishedConsumer();

    static class FinishedMessage extends HandshakeMessage {

        byte[] verifyData;

        FinishedMessage(byte[] verifyData) {
            this.verifyData = verifyData;
        }

        public FinishedMessage(ByteBuffer message) {
            verifyData = new byte[12];
            message.get(verifyData);
        }

        @Override
        SSLHandshakeType getHandshakeType() {
            return TYPE;
        }

        @Override
        byte[] getBytes() throws IOException {
            return verifyData;
        }

        @Override
        int messageLength() {
            return verifyData.length;//12
        }
    }

    static class FinishedConsumer implements HandshakeConsumer {

        @Override
        public void consume(HandshakeContext handshakeContext, ByteBuffer message) throws IOException {

            byte[] masterSecret = handshakeContext.handshakeSession.getMasterSecret();
            boolean isClientMode = handshakeContext.sslParameters.isClientMode();

            FinishedMessage finishedMessage = new FinishedMessage(message);
            byte[] hash = handshakeContext.handshakeHash.finish();

            String label = isClientMode ? "server finished" : "client finished";

            //验证服务端穿过来的
            try {
                byte[] expected =
                        Crypto.prf(masterSecret, label.getBytes(StandardCharsets.UTF_8), hash, 12);

                if (!Arrays.equals(expected, finishedMessage.verifyData)) {
                    throw new SSLException("Finished 验证消息失败");
                }

            } catch (Exception e) {
                throw new SSLException(e);
            }

            handshakeContext.isRecvFinish = true;

            if (handshakeContext.isSendFinish) {
                handshakeContext.handshakeFinished();
            } else {
                handshakeContext.switch2write();
            }

        }

        @Override
        public SSLHandshakeType handshakeType() {
            return TYPE;
        }
    }


    static class FinishedProducer implements HandshakeProducer {

        @Override
        public HandshakeMessage produce(HandshakeContext handshakeContext) throws SSLException, IOException {
            byte[] masterSecret = handshakeContext.handshakeSession.getMasterSecret();
            boolean isClientMode = handshakeContext.sslParameters.isClientMode();

            byte[] hash = handshakeContext.handshakeHash.finish();

            String label = isClientMode ? "client finished" : "server finished";
            FinishedMessage finishedMessage;
            //验证服务端穿过来的
            try {
                byte[] verifyData =
                        Crypto.prf(masterSecret, label.getBytes(StandardCharsets.UTF_8), hash, 12);

                finishedMessage = new FinishedMessage(verifyData);

            } catch (Exception e) {
                throw new SSLException(e);
            }

            handshakeContext.transportContext.sendChangeCipherSpec();

            return finishedMessage;
        }

        @Override
        public void finished(HandshakeContext handshakeContext) {

            handshakeContext.isSendFinish = true;
            if (handshakeContext.isRecvFinish) {
                handshakeContext.handshakeFinished();
            } else {
                handshakeContext.switch2read();
            }


        }
    }


}
