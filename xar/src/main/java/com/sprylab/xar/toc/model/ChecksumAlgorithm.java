package com.sprylab.xar.toc.model;

import com.sprylab.xar.XarException;
import com.sprylab.xar.XarSource;
import okio.ByteString;

public enum ChecksumAlgorithm {
    NONE("") {
        @Override
        public ByteString performHash(final ByteString data) {
            return ByteString.EMPTY;
        }
    },
    SHA1("3021300906052b0e03021a05000414") {
        @Override
        public ByteString performHash(final ByteString data) {
            return data.sha1();
        }
    },
    MD5("3020300c06082a864886f70d020505000410") {
        @Override
        public ByteString performHash(final ByteString data) {
            return data.md5();
        }
    };

    public static ChecksumAlgorithm fromXarSource(final XarSource xarSource) throws XarException {
        return ChecksumAlgorithm.values()[xarSource.getHeader().getCksumAlg().intValue()];
    }

    private final ByteString digestHeader;

    ChecksumAlgorithm(final String digestHeader) {
        this.digestHeader = ByteString.decodeHex(digestHeader);
    }

    public ByteString getDigestHeader() {
        return digestHeader;
    }

    public abstract ByteString performHash(ByteString data);

    @Override
    public String toString() {
        return super.toString().toLowerCase();
    }
}
