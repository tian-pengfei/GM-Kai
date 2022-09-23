package net.gmkai;

import net.gmkai.crypto.MacAlg;
import net.gmkai.crypto.TLSCrypto;
import net.gmkai.crypto.TLSPrf;
import net.gmkai.util.Bytes;

import javax.net.ssl.SSLException;

public abstract class ClientKeyExchangeNode extends HandshakeNode {


    @Override
    public final boolean consumable(HandshakeContext handshakeContext) {
        return false;
    }

    @Override
    public void doAfterConsume(HandshakeContext handshakeContext) throws SSLException {
        generateMasterSecret(handshakeContext);
    }

    @Override
    public final boolean optional(HandshakeContext handshakeContext) {
        return false;
    }

    @Override
    public void doAfterProduce(HandshakeContext handshakeContext) throws SSLException {
        generateMasterSecret(handshakeContext);
    }

    private void generateMasterSecret(HandshakeContext handshakeContext) throws SSLException {

        TLSCrypto tlsCrypto = handshakeContext.getTLSCrypto();
        TLSPrf tlsPrf = tlsCrypto.createTLSPrf(MacAlg.M_SM3);
        byte[] seed = Bytes.concat(handshakeContext.getClientRandom(), handshakeContext.getServerRandom());
        byte[] preMasterSecret = handshakeContext.getPreMasterSecret();
        handshakeContext.setMasterSecret(
                tlsPrf.prf(preMasterSecret, "master secret", seed, preMasterSecret.length));
    }

    @Override
    public HandshakeType getHandshakeType() {
        return HandshakeType.CLIENT_KEY_EXCHANGE;
    }
}
