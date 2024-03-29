package net.gmkai;

import com.google.common.collect.ImmutableList;

import javax.net.ssl.SSLException;

public class HandshakeNodes {

    final private ImmutableList<HandshakeNode> nodes;


    private final long id;

    private int pos = 0;

    public HandshakeNodes(ImmutableList<HandshakeNode> nodes, long id) {
        this.nodes = nodes;
        this.id = id;
    }

    boolean isConsumableTopNode(HandshakeContext handshakeContext) throws SSLException {

        if (pos == nodes.size()) throw new SSLException("All nodes have been executed ");

        return nodes.get(pos).consumable(handshakeContext);
    }

    HandshakeNode popHandshakeNode() {
        if (pos == nodes.size()) return null;
        synchronized (nodes) {
            return nodes.get(pos++);
        }
    }

    boolean isEmpty() {
        return pos == nodes.size();
    }

    public long getId() {
        return id;
    }

}
