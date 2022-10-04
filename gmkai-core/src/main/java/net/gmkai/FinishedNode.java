package net.gmkai;

import net.gmkai.crypto.MacAlg;
import net.gmkai.crypto.TLSCrypto;
import net.gmkai.crypto.TLSPrf;

import javax.net.ssl.SSLException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;

public class FinishedNode extends HandshakeNode {

    final static private String CLIENT_FINISHED_LABEL = "client finished";

    final static private String SERVER_FINISHED_LABEL = "server finished";

    final private HandshakeConsumable consumable;

    FinishedNode(HandshakeConsumable consumable) {
        this.consumable = consumable;
    }

    @Override
    public boolean consumable(HandshakeContext handshakeContext) {
        return consumable.consumable(handshakeContext);
    }

    @Override
    public void doAfterConsume(HandshakeContext handshakeContext) throws SSLException {
        handshakeContext.notifyPeerFinished();
    }

    @Override
    protected void doConsume(HandshakeContext handshakeContext, byte[] message) throws IOException {

        FinishedMsg finishedMsg = new FinishedMsg(ByteBuffer.wrap(message));

        String finishedLabel =
                handshakeContext.isClientMode() ? SERVER_FINISHED_LABEL : CLIENT_FINISHED_LABEL;

        TransportHasher transportHasher = handshakeContext.getTransportHasher();
        byte[] handshakeHash = transportHasher.getPreHash();
        byte[] expectedVerifyData = getVerifyData(handshakeContext, handshakeHash, finishedLabel);

        if (!Arrays.equals(expectedVerifyData, finishedMsg.verifyData)) {
            throw new SSLException("");
        }
    }

    @Override
    protected HandshakeMsg doProduce(HandshakeContext handshakeContext) throws IOException {
        handshakeContext.generateSecurityParameters();
        handshakeContext.changeWriteCipherSpec();

        FinishedMsg finishedMsg = new FinishedMsg();

        String finishedLabel =
                handshakeContext.isClientMode() ? CLIENT_FINISHED_LABEL : SERVER_FINISHED_LABEL;
        TransportHasher transportHasher = handshakeContext.getTransportHasher();
        byte[] handshakeHash = transportHasher.getCurrentHash();
        finishedMsg.verifyData = getVerifyData(handshakeContext, handshakeHash, finishedLabel);

        return finishedMsg;
    }

    @Override
    public HandshakeType getHandshakeType() {
        return HandshakeType.FINISHED;
    }

    @Override
    public boolean optional(HandshakeContext handshakeContext) {
        return false;
    }

    @Override
    public void doAfterProduce(HandshakeContext handshakeContext) throws SSLException {
        handshakeContext.notifySelfFinished();
    }

    private byte[] getVerifyData(HandshakeContext handshakeContext, byte[] handshakeHash, String finishedLabel) throws SSLException {

        TLSCrypto tlsCrypto = handshakeContext.getTLSCrypto();
        TLSPrf prf = tlsCrypto.createTLSPrf(MacAlg.M_SM3);


        return prf.prf(handshakeContext.getMasterSecret(), finishedLabel, handshakeHash, 12);
    }

    private static class FinishedMsg extends HandshakeMsg {
        byte[] verifyData;

        FinishedMsg() {
        }

        FinishedMsg(ByteBuffer buffer) throws IOException {
            super(buffer);
        }

        @Override
        HandshakeType getHandshakeType() {
            return null;
        }

        @Override
        byte[] getBody() throws IOException {
            return verifyData;
        }

        @Override
        int messageLength() {
            return 12;
        }

        @Override
        void parse(ByteBuffer buffer) throws IOException {
            verifyData = new byte[12];
            buffer.get(verifyData);
        }
    }
}
