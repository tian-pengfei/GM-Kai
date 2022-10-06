package net.gmkai;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;

import javax.net.ssl.SSLException;

public class HandshakeAssembler {

    //todo centralize handshakeNodes and Matcher ,configurable,id

    static final ImmutableList<HandshakeNode> tlcp11HandshakeNodes =
            ImmutableList.of(
                    new CertificateNode(hc -> !hc.isClientMode(), HandshakeContext::isClientMode),
                    new ServerSimpleKeyExchangeNode(),
//                    new CertificateRequest(hc->!hc.isNeedAuthClient()),
                    new ServerHelloDoneNode(),
                    new CertificateNode(hc -> !hc.isNeedAuthClient(), hc -> !hc.isClientMode()),
                    new ClientSimpleKeyExchangeNode(),
//                    new CertificateVerify(hc->!hc.isNeedAuthClient()),
                    new FinishedNode(hc -> !hc.isClientMode()),
                    new FinishedNode(HandshakeContext::isClientMode));


    static final ImmutableMap<Long, ImmutableList<HandshakeNode>> handshakeNodesMap =
            ImmutableMap.of(0x00101e013L, tlcp11HandshakeNodes);

    HandshakeNodes assemble(final NegotiationResult result) throws SSLException {

        ImmutableList<HandshakeNode> handshakeNodes = handshakeNodesMap.get(result.id);

        if (handshakeNodes == null) throw new SSLException("internal error :no exist corresponding handshake nodes");

        return new HandshakeNodes(handshakeNodes, result.id);
    }

}
