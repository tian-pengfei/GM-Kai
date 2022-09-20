package net.gmkai;

import net.gmkai.crypto.TLSHash;

public interface Hashable {

    byte[] getCurrentHash();

    byte[] getPreHash();

    void reset();

    void init(TLSHash tlsHash);
}
