package net.gmkai;

import com.google.common.collect.ImmutableList;
import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;

public class HandshakeNodesTest {


    @Test
    public void should_pop_handshake_node() {

        ImmutableList<HandshakeNode> nodes =
                ImmutableList.of(new ClientSimpleKeyExchangeNode(), new ServerHelloDoneNode());

        HandshakeNodes handshakeNodes = new HandshakeNodes(nodes, 123L);
        assertThat(handshakeNodes.getId(), is(123L));
        for (HandshakeNode node : nodes) {
            HandshakeNode _node = handshakeNodes.popHandshakeNode();

            assertThat(_node, is(notNullValue()));
            assertThat(node.getClass(), is(_node.getClass()));
        }
        assertThat(handshakeNodes.isEmpty(), is(true));
    }
}
