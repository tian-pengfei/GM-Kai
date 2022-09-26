package net.gmkai;

import javax.net.ssl.SSLException;
import java.io.IOException;

public class HandshakeExecutor {

    private final HandshakeMsgTransport transport;

    private final HandshakeContext handshakeContext;

    static final String NOT_FOUND_CONSUME_NODE = "a suitable consume-node could not be found";
    static final String NOT_FOUND_PRODUCE_NODE = "a suitable produce-node could not be found";
    static final String WRONG_TYPE_NODE = "node doesn't match the type of msg";

    public HandshakeExecutor(HandshakeMsgTransport transport, HandshakeContext handshakeContext) {
        this.transport = transport;
        this.handshakeContext = handshakeContext;
    }

    public synchronized void execute(HandshakeNodes handshakeNodes) throws IOException {

        while (!handshakeNodes.isEmpty()) {
            HandshakeNode node = executeTopNode(handshakeNodes);
            node.doAfter(handshakeContext);
        }
    }


    private HandshakeNode executeTopNode(HandshakeNodes handshakeNodes) throws IOException {

        boolean consumable = handshakeNodes.isConsumableTopNode(handshakeContext);
        if (consumable) {
            return executeTopConsumeNode(handshakeNodes);
        }
        return executeTopProduceNode(handshakeNodes);

    }

    /**
     * when  consume operation is executed and
     * first rev handshake message doesn't match type of top node,
     * top node must be optional,otherwise an error is reported;
     *
     * @param handshakeNodes Node execution queue
     * @return was executed HandshakeNode
     * @throws IOException no suitable node was found
     */
    private HandshakeNode executeTopConsumeNode(HandshakeNodes handshakeNodes) throws IOException {

        HandshakeMsg handshakeMsg = null;

        while (!handshakeNodes.isEmpty()) {
            if (!handshakeNodes.isConsumableTopNode(handshakeContext)) {
                throw new SSLException(NOT_FOUND_CONSUME_NODE);
            }

            if (handshakeMsg == null) {
                handshakeMsg = transport.readHandshakeMsg();
            }

            HandshakeNode node = handshakeNodes.popHandshakeNode();
            if (node.getHandshakeType() == handshakeMsg.getHandshakeType()) {
                node.consume(handshakeContext, handshakeMsg.getMsg());
                return node;
            }

            if (!node.optional(handshakeContext)) {
                throw new SSLException(WRONG_TYPE_NODE);
            }

        }
        throw new SSLException(NOT_FOUND_CONSUME_NODE);
    }

    /**
     * when  produce operation is executed,
     * execute produce option produce node must be required (optional is false)
     * otherwise skip to execute the next node;
     *
     * @param handshakeNodes Node execution queue
     * @return was executed HandshakeNode
     * @throws IOException no suitable node was found
     */
    private HandshakeNode executeTopProduceNode(HandshakeNodes handshakeNodes) throws IOException {
        while (!handshakeNodes.isEmpty()) {
            if (handshakeNodes.isConsumableTopNode(handshakeContext)) {
                throw new SSLException(NOT_FOUND_PRODUCE_NODE);
            }

            HandshakeNode node = handshakeNodes.popHandshakeNode();
            if (node.optional(handshakeContext)) {
                continue;
            }
            HandshakeMsg handshakeMsg = node.produce(handshakeContext);
            transport.writeHandshakeMsg(handshakeMsg);
            return node;
        }

        throw new SSLException(NOT_FOUND_PRODUCE_NODE);
    }
}
