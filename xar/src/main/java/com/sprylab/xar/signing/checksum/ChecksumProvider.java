package com.sprylab.xar.signing.checksum;

import okio.ByteString;
import okio.HashingSource;
import okio.Source;

public abstract class ChecksumProvider {
    private HashingSource hashingSource;

    /**
     * @param source the source over which to calculate the checksum
     * @return the wrapped source, over which the checksum will be calculated
     */
    public Source wrap(final Source source) {
        this.hashingSource = this.buildHashingSource(source);
        return this.hashingSource;
    }

    /**
     * @return the calculated checksum
     * @throws IllegalStateException when there's no source over which to calculate the checksum
     */
    public ByteString getChecksum() throws IllegalStateException {
        if (hashingSource == null) {
            throw new IllegalStateException("A source should be wrapped with a provider before retrieving the checksum");
        }

        return hashingSource.hash();
    }

    protected abstract HashingSource buildHashingSource(Source source);
}
