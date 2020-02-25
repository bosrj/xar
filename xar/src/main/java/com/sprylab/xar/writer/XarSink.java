package com.sprylab.xar.writer;

import java.io.IOException;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.Deflater;

import com.sprylab.xar.XarHeader;
import com.sprylab.xar.toc.TocFactory;
import com.sprylab.xar.toc.model.*;

import okio.Buffer;
import okio.BufferedSource;
import okio.ByteString;
import okio.DeflaterSink;
import okio.Okio;
import okio.Sink;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

public class XarSink {

    private static final long CHECKSUM_LENGTH_MD5 = 16L;

    private static final long CHECKSUM_LENGTH_SHA1 = 20L;

    private final ChecksumAlgorithm checksumAlgorithm;

    private final ToC toc = new ToC();

    private final List<File> files = new ArrayList<>();

    private final List<XarEntrySource> sources = new ArrayList<>();

    private final Map<XarDirectory, File> dirMap = new HashMap<>();

    private long currentOffset;

    private int id;

    private List<X509Certificate> certChain = null;

    private PrivateKey signKey = null;

    public XarSink() {
        this(ChecksumAlgorithm.SHA1);
    }

    public XarSink(final ChecksumAlgorithm checksumAlgorithm) {
        this.checksumAlgorithm = checksumAlgorithm;
        final long checksumLength;
        switch (checksumAlgorithm) {
            default:
            case NONE:
                checksumLength = 0L;
                break;
            case SHA1:
                checksumLength = CHECKSUM_LENGTH_SHA1;
                break;
            case MD5:
                checksumLength = CHECKSUM_LENGTH_MD5;
                break;
        }
        toc.setCreationTime(new Date());
        toc.setFiles(files);
        final Checksum checksum = new Checksum(checksumAlgorithm, checksumLength, 0L);
        toc.setChecksum(checksum);
        this.currentOffset = checksumLength;
    }

    public void addSigning(final List<X509Certificate> certChain, final PrivateKey signKey) throws IOException {
        if ((checksumAlgorithm == null) || (checksumAlgorithm == ChecksumAlgorithm.NONE)) {
            throw new IllegalStateException("No checksum algorithm has been selected, so it is not possible to add signing");
        } else if (this.signKey != null) {
            throw new IllegalStateException("Signing key has already been added");
        } else if (!files.isEmpty()) {
            throw new IllegalStateException("Signing key should be added before any files are added");
        }

        this.certChain = certChain;
        this.signKey = signKey;

        // Add signature
        final Signature sig = new Signature(certChain, "RSA", (int) currentOffset, 256);
        currentOffset += sig.getSize();
        toc.setSignature(sig);

        // Add xSignature
        try {
            final Signature xSig = new Signature(certChain, "CMS", (int) currentOffset, createCMSSignature(ByteString.EMPTY).size());
            currentOffset += xSig.getSize();
            toc.setXSignature(xSig);
        } catch (final OperatorCreationException | CertificateException | IOException | CMSException ex) {
            throw new IOException("Failed to generate the dummy CMS signature", ex);
        }
    }

    public void addSource(final XarEntrySource source) {
        addSource(source, null);
    }

    public void addSource(final XarEntrySource source, final XarDirectory parent) {
        sources.add(source);
        final File file = new File();
        file.setType(Type.FILE);
        file.setName(source.getName());
        file.setId(String.valueOf(id++));
        final Date lastModifiedDate = new Date(source.getLastModified());
        file.setMtime(lastModifiedDate);
        file.setCtime(lastModifiedDate);
        final Data data = new Data();
        data.setOffset(currentOffset);
        data.setLength(source.getLength());
        data.setSize(source.getSize());
        currentOffset += source.getLength();

        final ChecksumAlgorithm checksumStyle = source.getChecksumAlgorithm();
        if (checksumStyle != null && checksumStyle != ChecksumAlgorithm.NONE) {
            final SimpleChecksum extractedChecksum = new SimpleChecksum();
            extractedChecksum.setStyle(checksumStyle);
            extractedChecksum.setValue(source.getExtractedChecksum() == null ? "0" : source.getExtractedChecksum());
            data.setExtractedChecksum(extractedChecksum);
            data.setUnarchivedChecksum(extractedChecksum);

            final SimpleChecksum archivedChecksum = new SimpleChecksum();
            archivedChecksum.setStyle(checksumStyle);
            archivedChecksum.setValue(source.getArchivedChecksum() == null ? "0" : source.getArchivedChecksum());
            data.setArchivedChecksum(archivedChecksum);
        }

        data.setEncoding(source.getEncoding());
        file.setData(data);
        addFile(file, parent);
    }

    public void addDirectory(final XarDirectory dir, final XarDirectory parent) {
        final File file = new File();
        file.setType(Type.DIRECTORY);
        file.setName(dir.getName());
        file.setId(String.valueOf(id++));
        addFile(file, parent);
        dirMap.put(dir, file);
    }

    private void addFile(final File file, final XarDirectory parent) {
        if (parent == null) {
            files.add(file);
        } else {
            final File parentFile = dirMap.get(parent);
            if (parentFile == null) {
                throw new IllegalArgumentException("Unknown parent.");
            }
            List<File> children = parentFile.getChildren();
            if (children == null) {
                children = new ArrayList<>();
                parentFile.setChildren(children);
            }
            children.add(file);
        }
    }

    public void write(final OutputStream output) throws Exception {
        try (final Buffer buffer = new Buffer()) {
            final long tocBufferSize;
            final Buffer tocCompressedBuffer;
            try (final Buffer tocBuffer = new Buffer()) {
                TocFactory.toOutputStream(toc, tocBuffer.outputStream());
                tocBufferSize = tocBuffer.size();

                tocCompressedBuffer = new Buffer();

                try (final Sink deflaterSink = new DeflaterSink(tocCompressedBuffer, new Deflater(Deflater.BEST_COMPRESSION))) {
                    deflaterSink.write(tocBuffer, tocBuffer.size());
                }
            }

            final ByteString tocCompressed = tocCompressedBuffer.readByteString(tocCompressedBuffer.size());
            final ByteString tocCompressedBufferHash = checksumAlgorithm.performHash(tocCompressed);

            buffer.write(XarHeader.createHeader(tocCompressed.size(), tocBufferSize, checksumAlgorithm));
            buffer.write(tocCompressed);

            if (tocCompressedBufferHash != null) {
                buffer.write(tocCompressedBufferHash);

                if (hasSigning()) {
                    if (toc.getSignature() != null) {
                        buffer.write(createRSASignature(tocCompressedBufferHash));
                    }

                    if (toc.getXSignature() != null) {
                        buffer.write(createCMSSignature(tocCompressedBufferHash));
                    }
                }
            }

            try (final Sink sink = Okio.sink(output)) {
                // Write header and ToC
                buffer.readAll(sink);

                // Write entries
                for (final XarEntrySource xs : sources) {
                    try (final BufferedSource source = Okio.buffer(xs.getSource())) {
                        source.readAll(sink);
                    }
                }
            }
        }
    }

    private byte[] createRSASignature(final ByteString tocCompressedBufferHash)
        throws NoSuchAlgorithmException, InvalidKeyException, SignatureException
    {
        final String signatureStyle = checksumAlgorithm.toString().toUpperCase() + "with" + toc.getSignature().getStyle();
        final java.security.Signature sigAlg = java.security.Signature.getInstance(signatureStyle);

        sigAlg.initSign(signKey);
        sigAlg.update(tocCompressedBufferHash.asByteBuffer());
        final byte[] signature = sigAlg.sign();
        if (signature.length != toc.getSignature().getSize()) {
            throw new IllegalStateException("The generated signature is of a different length than expected");
        }
        return signature;
    }

    private ByteString createCMSSignature(final ByteString checksum)
        throws OperatorCreationException, CertificateException, IOException, CMSException
    {
        final CMSSignedDataGenerator generator = new CMSSignedDataGenerator();

        // Add the signing info
        final ContentSigner contentSigner = new JcaContentSignerBuilder(checksumAlgorithm + "withRSA").build(signKey);
        final X509CertificateHolder signingCertificate = new X509CertificateHolder(certChain.get(0).getEncoded());
        generator.addSignerInfoGenerator(
            new JcaSignerInfoGeneratorBuilder(
                new JcaDigestCalculatorProviderBuilder()
                    .setProvider("BC")
                    .build()).build(contentSigner, signingCertificate));

        // Add the certificate chain in reverse order
        for (int ix = certChain.size() - 1; ix >= 0; ix--) {
            generator.addCertificate(new X509CertificateHolder(certChain.get(ix).getEncoded()));
        }

        // Generate the signature
        final CMSSignedData signedData = generator.generate(new CMSProcessableByteArray(checksum.toByteArray()), false);

        // And return the encoded signature
        final ByteString result = ByteString.of(signedData.getEncoded());
        if ((toc.getXSignature() != null) && (result.size() != toc.getXSignature().getSize())) {
            throw new IllegalStateException("The generated signature is of a different length than expected");
        }
        return result;
    }

    private boolean hasSigning() {
        return certChain != null
            && certChain.size() > 0
            && signKey != null;
    }
}
