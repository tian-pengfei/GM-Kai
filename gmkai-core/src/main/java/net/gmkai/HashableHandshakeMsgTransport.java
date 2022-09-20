package net.gmkai;

import net.gmkai.crypto.TLSHash;

import java.io.IOException;
import java.util.LinkedList;
import java.util.List;

public class HashableHandshakeMsgTransport implements Hashable, HandshakeMsgTransport {

    private final List<byte[]> handshakeMsgs = new LinkedList<>();

    private TLSHash tlsHash;

    private final HandshakeMsgTransport handshakeMsgTransport;

    private byte[] currentHash;

    private byte[] preHash;

    public HashableHandshakeMsgTransport(HandshakeMsgTransport handshakeMsgTransport) {
        this.handshakeMsgTransport = handshakeMsgTransport;
    }

    @Override
    public TLSText readHandshakeMsg() throws IOException {
        TLSText tlsText = handshakeMsgTransport.readHandshakeMsg();
        addData(tlsText.fragment);
        return tlsText;
    }

    @Override
    public void writeHandshakeMsg(byte[] data) throws IOException {

        handshakeMsgTransport.writeHandshakeMsg(data);
        addData(data);
    }

    @Override
    public byte[] getCurrentHash() {
        verifyTLSHash();
        if (currentHash != null) return currentHash;
        handshakeMsgs.
                forEach(handshakeMsg -> tlsHash.update(handshakeMsg, 0, handshakeMsg.length));
        currentHash = tlsHash.calculateHash();

        return currentHash;
    }

    @Override
    public byte[] getPreHash() {
        verifyTLSHash();

        if (preHash != null) return preHash;
        if (handshakeMsgs.size() == 0) throw new RuntimeException();

        for (int i = 0; i < handshakeMsgs.size() - 1; i++) {
            tlsHash.update(handshakeMsgs.get(i), 0, handshakeMsgs.get(i).length);
        }

        preHash = tlsHash.calculateHash();
        return preHash;
    }

    @Override
    public void reset() {

        preHash = null;
        currentHash = null;

        handshakeMsgs.clear();
    }

    @Override
    public void init(TLSHash tlsHash) {
        if (this.tlsHash != null) throw new RuntimeException();
        this.tlsHash = tlsHash;
    }

    private void addData(byte[] data) {
        preHash = currentHash;
        currentHash = null;
        handshakeMsgs.add(data);
    }

    private void verifyTLSHash() {
        if (tlsHash == null)
            throw new NullPointerException();
    }
}
