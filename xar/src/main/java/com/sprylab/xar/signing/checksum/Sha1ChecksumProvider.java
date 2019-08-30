package com.sprylab.xar.signing.checksum;

import okio.HashingSource;
import okio.Source;

public class Sha1ChecksumProvider extends ChecksumProvider {
    @Override
    protected HashingSource buildHashingSource(final Source source) {
        return HashingSource.sha1(source);
    }
}
