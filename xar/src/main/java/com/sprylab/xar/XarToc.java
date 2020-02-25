package com.sprylab.xar;

import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Stack;

import com.sprylab.xar.signing.checksum.ChecksumProvider;
import com.sprylab.xar.signing.checksum.ChecksumProviderFactory;
import com.sprylab.xar.toc.TocFactory;
import com.sprylab.xar.toc.model.Checksum;
import com.sprylab.xar.toc.model.Signature;
import com.sprylab.xar.toc.model.ToC;
import com.sprylab.xar.utils.FilePath;
import com.sprylab.xar.utils.StringUtils;

import okio.ByteString;

/**
 * Describes the table of content of an eXtensible ARchiver file represented by a {@link XarSource}
 * (see <a href="https://github.com/mackyle/xar/wiki/xarformat#The_Table_of_Contents">specification</a>).
 */
public class XarToc {

    private final ToC model;

    private final List<XarEntry> entries = new ArrayList<>();

    private final Map<String, XarEntry> nameToEntryMap = new HashMap<>();

    private final XarSource xarSource;

    private ByteString calculatedChecksum = null;

    private X509Certificate signCertificate;
    private X509Certificate xSignCertificate;

    public XarToc(final XarSource xarSource) throws XarException {
        this.xarSource = xarSource;

        final ChecksumProvider checksumProvider = ChecksumProviderFactory.fromXarSource(xarSource);
        try (final InputStream inputStream = xarSource.getToCStream(checksumProvider)) {
            this.model = TocFactory.fromInputStream(inputStream);
            createEntries();

            if (xarSource.isVerifyCerts()) {
                try {
                    if (signCertificate != null)
                        signCertificate.checkValidity();
                    if (xSignCertificate != null)
                        xSignCertificate.checkValidity();
                } catch (final CertificateException e) {
                    throw new XarException("Signature certificates are no longer valid", e);
                }
            }

            try {
                calculatedChecksum = checksumProvider.getChecksum();
            } catch (final IllegalStateException ignore) {
                // Could not calculate checksum
            }
        } catch (final Exception e) {
            throw new XarException("Could not create toc", e);
        }
    }

    public X509Certificate getSignCertificate() {
        return signCertificate;
    }

    public void setSignCertificate(final X509Certificate signCertificate) {
        this.signCertificate = signCertificate;
    }

    public X509Certificate getXSignCertificate() {
        return xSignCertificate;
    }

    public void setXSignCertificate(final X509Certificate xSignCertificate) {
        this.xSignCertificate = xSignCertificate;
    }

    private void createEntries() throws XarException {
        // Unfortunately simple-xml throws Exceptions
        //noinspection OverlyBroadCatchBlock
        final Stack<FilePath> fileStack = new Stack<>();
        fileStack.addAll(FilePath.fromFileList(this.model.getFiles()));

        while (!fileStack.isEmpty()) {
            final FilePath currentFile = fileStack.pop();
            final com.sprylab.xar.toc.model.File fileEntry = currentFile.getFile();
            final XarEntry xarEntry = XarEntry.createFromXarSource(this.xarSource, fileEntry, currentFile.getParentPath());

            if (xarEntry.isDirectory()) {
                final List<com.sprylab.xar.toc.model.File> children = fileEntry.getChildren();
                if (children != null && !children.isEmpty()) {
                    fileStack.addAll(FilePath.fromFileList(children, xarEntry.getName()));
                }
            }
            addEntry(xarEntry);
            addToParentEntry(xarEntry, currentFile.getParentPath());
        }
    }

    private void addEntry(final XarEntry xarEntry) {
        entries.add(xarEntry);
        nameToEntryMap.put(xarEntry.getName(), xarEntry);
    }

    private void addToParentEntry(final XarEntry xarEntry, final String parentPath) {
        if (StringUtils.isEmpty(parentPath)) {
            // the entry itself is in the root entry
            return;
        }
        final XarEntry parentEntry = nameToEntryMap.get(parentPath);
        parentEntry.addChild(xarEntry);
    }

    public List<XarEntry> getEntries() {
        return entries;
    }

    public XarEntry getEntry(final String entryName) {
        return nameToEntryMap.get(entryName);
    }

    public boolean hasEntry(final String entryName) {
        return nameToEntryMap.containsKey(entryName);
    }

    public Checksum getChecksum() {
        return model.getChecksum();
    }

    public Signature getSignature() {
        return model.getSignature();
    }

    public Signature getXSignature() {
        return model.getXSignature();
    }

    public ByteString getCalculatedChecksum() {
        return calculatedChecksum;
    }
}
