package net.gmkai;

import net.gmkai.crypto.BulkCipherAlg;
import net.gmkai.crypto.MacAlg;

/**
 * struct {
 * ConnectionEnd          entity;
 * PRFAlgorithm           prf_algorithm;
 * BulkCipherAlgorithm    bulk_cipher_algorithm;
 * CipherType             cipher_type;
 * uint8                  enc_key_length;
 * uint8                  block_length;
 * uint8                  fixed_iv_length;
 * uint8                  record_iv_length;
 * MACAlgorithm           mac_algorithm;
 * uint8                  mac_length;
 * uint8                  mac_key_length;
 * CompressionMethod      compression_algorithm;
 * opaque                 master_secret[48];
 * opaque                 client_random[32];
 * opaque                 server_random[32];
 * } SecurityParameters;
 */

public class SecurityParameters {

    final private ConnectionEnd connectionEnd;

    final private BulkCipherAlg bulkCipherAlg;

    final private MacAlg macAlg;

    final private CompressionMethod compressionMethod = CompressionMethod.NULL;

    final private byte[] masterSecret;

    final private byte[] clientRandom;

    final private byte[] serverRandom;

    final private int recordIvLength;

    SecurityParameters(ConnectionEnd connectionEnd, BulkCipherAlg bulkCipherAlg, MacAlg macAlg, byte[] masterSecret, byte[] clientRandom, byte[] serverRandom, int recordIvLength) {
        this.connectionEnd = connectionEnd;
        this.bulkCipherAlg = bulkCipherAlg;
        this.macAlg = macAlg;
        this.masterSecret = masterSecret;
        this.clientRandom = clientRandom;
        this.serverRandom = serverRandom;
        this.recordIvLength = recordIvLength;
    }

    public ConnectionEnd getConnectionEnd() {
        return connectionEnd;
    }

    public BulkCipherAlg getBulkCipherAlg() {
        return bulkCipherAlg;
    }

    public MacAlg getMacAlg() {
        return macAlg;
    }

    public CompressionMethod getCompressionMethod() {
        return compressionMethod;
    }

    public byte[] getMasterSecret() {
        return masterSecret;
    }

    public byte[] getClientRandom() {
        return clientRandom;
    }

    public byte[] getServerRandom() {
        return serverRandom;
    }

    public int getRecordIvLength() {
        return recordIvLength;
    }

    public int getMacLength() {
        return macAlg.getMacLength();
    }

    public int getIvLength() {
        return bulkCipherAlg.ivLength;
    }

    public static final class SecurityParametersBuilder {
        private ConnectionEnd connectionEnd;
        private BulkCipherAlg bulkCipherAlg;
        private MacAlg macAlg;
        private byte[] masterSecret;
        private byte[] clientRandom;
        private byte[] serverRandom;
        private int recordIvLength;

        private SecurityParametersBuilder() {
        }

        public static SecurityParametersBuilder aSecurityParameters() {
            return new SecurityParametersBuilder();
        }

        public SecurityParametersBuilder withConnectionEnd(ConnectionEnd connectionEnd) {
            this.connectionEnd = connectionEnd;
            return this;
        }

        public SecurityParametersBuilder withBulkCipherAlg(BulkCipherAlg bulkCipherAlg) {
            this.bulkCipherAlg = bulkCipherAlg;
            return this;
        }

        public SecurityParametersBuilder withMacAlg(MacAlg macAlg) {
            this.macAlg = macAlg;
            return this;
        }

        public SecurityParametersBuilder withMasterSecret(byte[] masterSecret) {
            this.masterSecret = masterSecret;
            return this;
        }

        public SecurityParametersBuilder withClientRandom(byte[] clientRandom) {
            this.clientRandom = clientRandom;
            return this;
        }

        public SecurityParametersBuilder withServerRandom(byte[] serverRandom) {
            this.serverRandom = serverRandom;
            return this;
        }

        public SecurityParametersBuilder withRecordIvLength(int recordIvLength) {
            this.recordIvLength = recordIvLength;
            return this;
        }

        public SecurityParameters build() {
            return new SecurityParameters(connectionEnd, bulkCipherAlg, macAlg, masterSecret, clientRandom, serverRandom, recordIvLength);
        }
    }
}
