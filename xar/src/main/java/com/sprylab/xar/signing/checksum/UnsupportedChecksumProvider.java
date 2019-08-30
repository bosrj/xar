package com.sprylab.xar.signing.checksum;

import okio.ByteString;
import okio.HashingSource;
import okio.Source;

public class UnsupportedChecksumProvider extends ChecksumProvider {
    @Override
    public Source wrap(final Source source) {
        return source;
    }

    @Override
    public ByteString getChecksum() {
        throw new IllegalStateException("This checksum algorithm is not supported");
    }

    @Override
    protected HashingSource buildHashingSource(final Source source) {
        return null;
    }
}
