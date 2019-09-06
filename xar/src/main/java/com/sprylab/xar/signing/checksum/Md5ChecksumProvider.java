package com.sprylab.xar.signing.checksum;

import okio.HashingSource;
import okio.Source;

public class Md5ChecksumProvider extends ChecksumProvider {
    @Override
    protected HashingSource buildHashingSource(final Source source) {
        return HashingSource.md5(source);
    }
}
