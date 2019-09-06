package com.sprylab.xar.signing.checksum;

import com.sprylab.xar.XarException;
import com.sprylab.xar.XarSource;
import com.sprylab.xar.toc.model.ChecksumAlgorithm;

public class ChecksumProviderFactory {
    /**
     * Creates the appropriate ChecksumProvider given the XarSource
     *
     * @param xarSource the {@link XarSource} for which the checksum needs to be calculated
     * @return the checksum provider for calculating the checksum
     * @throws XarException when the checksum algorithm could not be determined
     */
    public static ChecksumProvider fromXarSource(final XarSource xarSource) throws XarException {
        final ChecksumAlgorithm checksumAlgorithm = ChecksumAlgorithm.fromXarSource(xarSource);

        if (checksumAlgorithm == ChecksumAlgorithm.SHA1) {
            return new Sha1ChecksumProvider();
        } else if (checksumAlgorithm == ChecksumAlgorithm.MD5) {
            return new Md5ChecksumProvider();
        } else {
            // Unsupported algorithm, return dummy provider
            return new UnsupportedChecksumProvider();
        }
    }
}
