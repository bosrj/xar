package com.sprylab.xar.signing;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collection;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.OperatorCreationException;

import com.sprylab.xar.XarException;
import com.sprylab.xar.XarSource;
import com.sprylab.xar.XarToc;
import com.sprylab.xar.toc.model.ChecksumAlgorithm;
import com.sprylab.xar.toc.model.Signature;

import okio.BufferedSource;
import okio.ByteString;

public class TocCertificateParser {
    private final XarSource xarSource;

    private boolean parsed;
    private final int baseOffset;

    private X509Certificate signCertificate;
    private X509Certificate xSignCertificate;

    /**
     * @param xarSource The {@link XarSource} for which certificates should be extracted
     * @throws XarException when there is an error setting up the extractor
     */
    public TocCertificateParser(final XarSource xarSource) throws XarException {
        this.xarSource = xarSource;
        this.parsed = false;
        this.baseOffset = xarSource.getHeader().getSize().intValue() + xarSource.getHeader().getTocLengthCompressed().intValue();
    }

    /**
     * @return the certificate associated with the signature element in the source's {@link com.sprylab.xar.toc.model.ToC ToC}
     */
    public X509Certificate getSignCertificate() {
        return signCertificate;
    }

    /**
     * @return the certificate associated with the x-signature element in the source's {@link com.sprylab.xar.toc.model.ToC ToC}
     */
    public X509Certificate getXSignCertificate() {
        return xSignCertificate;
    }

    /**
     * Start extracting the certificates
     *
     * @throws XarException when there is an error while extracting the certificates
     */
    public void parse() throws XarException {
        final XarToc toc = xarSource.getToc();

        if (parsed || toc.getSignCertificate() != null || toc.getXSignCertificate() != null) {
            return;
        } else {
            parsed = true;
        }

        // Determine the checksum algorithm
        final ChecksumAlgorithm checksumAlgorithm = ChecksumAlgorithm.fromXarSource(xarSource);
        if (checksumAlgorithm == ChecksumAlgorithm.NONE) {
            // Nothing to check
            throw new IllegalStateException("Cannot parse signature information when there is no checksum");
        }

        // Determine if the stored checksum matches the actual ToC checksum
        verifyChecksum(toc);

        // Parse signCertificate and xSignCertificate
        try {
            parseCertificate(toc.getSignature(), checksumAlgorithm);
            parseXCertificate(toc.getXSignature());
        } catch (final CertificateException | SignatureException | IOException e) {
            throw new XarException("Error parsing the signature information of ToC", e);
        }
    }

    /**
     * @param signature the signature for which to read the certificate
     * @param checksumAlgorithm the checksum algorithm for the source xar
     * @throws CertificateException when there is an error while extracting the X.509 certificate
     * @throws SignatureException when there is an error while verifying the signature
     * @throws IOException when there is an error while reading the signature from the source ToC
     */
    private void parseCertificate(final Signature signature, final ChecksumAlgorithm checksumAlgorithm)
        throws CertificateException, SignatureException, IOException
    {
        if (signature != null) {
            final X509Certificate certificate = loadCertificate(signature);
            verifySignature(certificate, signature, checksumAlgorithm, readStoredSignature(signature));     // SignatureException

            signCertificate = certificate;
        }
    }

    /**
     * @param xSignature the x-signature for which to read the certificate
     * @throws CertificateException when there is an error while extracting the X.509 certificate
     * @throws SignatureException when there is an error while verifying the x-signature
     * @throws IOException when there is an error while reading the x-signature from the source ToC
     */
    private void parseXCertificate(final Signature xSignature)
        throws CertificateException, SignatureException, IOException
    {
        if (xSignature != null) {
            final X509Certificate xCertificate = loadCertificate(xSignature, "CMS");
            verifyCMSSignature(readStoredSignature(xSignature));

            xSignCertificate = xCertificate;
        }
    }

    /**
     * Verifies the signature from the ToC with the extracted X.509 certificate
     *
     * @param certificate the X.509 certificate to match with the signature
     * @param signature the signature data from the ToC
     * @param checksumAlgorithm the checksum algorithm for the source xar
     * @param sigBytes the binary signature as read from the source ToC
     * @throws SignatureException when there is an error while verifying the signature given the certificate
     * @throws XarException when there is an error while reading the stored checksum from the source xar
     */
    private void verifySignature(final X509Certificate certificate,
                                 final Signature signature,
                                 final ChecksumAlgorithm checksumAlgorithm,
                                 final ByteString sigBytes)
        throws SignatureException, XarException
    {
        verifySignature(certificate, signature, checksumAlgorithm, sigBytes, false);
    }

    /**
     * Verifies the signature from the ToC with the extracted X.509 certificate
     *
     * @param certificate the X.509 certificate to match with the signature
     * @param signature the signature data from the ToC
     * @param checksumAlgorithm the checksum algorithm for the source xar
     * @param sigBytes the binary signature as read from the source ToC
     * @param digestHeaderInData whether the digest header has been incorporated in the signed data.
     *                           If this value is false and the signature cannot be verified, a retry will be done
     *                           with 'true' for this value
     * @throws SignatureException when there is an error while verifying the signature given the certificate
     * @throws XarException when there is an error while reading the stored checksum from the source xar
     */
    private void verifySignature(final X509Certificate certificate,
                                 final Signature signature,
                                 final ChecksumAlgorithm checksumAlgorithm,
                                 final ByteString sigBytes,
                                 final boolean digestHeaderInData)
        throws SignatureException, XarException
    {
        try {
            String digest = !digestHeaderInData ? checksumAlgorithm.toString().toUpperCase() : "NONE";
            String signatureStyle = digest + "with" + signature.getStyle();

            final java.security.Signature sigAlg = java.security.Signature.getInstance(signatureStyle);
            sigAlg.initVerify(certificate.getPublicKey());

            if (digestHeaderInData) {
                sigAlg.update(checksumAlgorithm.getDigestHeader().asByteBuffer());
            }

            sigAlg.update(xarSource.getStoredChecksum().asByteBuffer());

            if (!sigAlg.verify(sigBytes.toByteArray())) {
                if (!digestHeaderInData) {
                    retryVerifySignature(certificate, signature, checksumAlgorithm, sigBytes);
                } else {
                    throw new SignatureException("Signature does not match the checksum");
                }
            }
        } catch (final NoSuchAlgorithmException | InvalidKeyException e) {
            throw new SignatureException("Signature could not be verified", e);
        }
    }

    /**
     * Retries verifying the signature from the ToC with the extracted X.509 certificate
     *
     * @param certificate the X.509 certificate to match with the signature
     * @param signature the signature data from the ToC
     * @param checksumAlgorithm the checksum algorithm for the source xar
     * @param sigBytes the binary signature as read from the source ToC
     * @throws SignatureException when there is an error while verifying the signature given the certificate
     * @throws XarException when there is an error while reading the stored checksum from the source xar
     */
    private void retryVerifySignature(final X509Certificate certificate,
                                      final Signature signature,
                                      final ChecksumAlgorithm checksumAlgorithm,
                                      final ByteString sigBytes)
        throws SignatureException, XarException
    {
        verifySignature(certificate, signature, checksumAlgorithm, sigBytes, true);
    }

    /**
     * Verifies the x-signature from the ToC with the extracted X.509 certificate
     *
     * @param sigBytes the binary signature data as read from the source xar
     * @throws SignatureException when there is an error while verifying the signature given the certificate
     * @throws XarException when there is an error while reading the stored checksum from the source xar
     */
    private void verifyCMSSignature(final ByteString sigBytes) throws SignatureException, XarException {
        try {
            final CMSSignedData signedData = new CMSSignedData(new CMSProcessableByteArray(xarSource.getStoredChecksum().toByteArray()),
                sigBytes.toByteArray());

            final Collection<X509CertificateHolder> certHolders = signedData.getCertificates().getMatches(null);
            X509CertificateHolder lastCertHolder = null;
            for (final X509CertificateHolder holder : certHolders) {
                lastCertHolder = holder;
            }

            final Collection<SignerInformation> signers = signedData.getSignerInfos().getSigners();
            for (final SignerInformation signer : signers) {
                final SignerInformationVerifier verifier = new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(lastCertHolder);

                if (!signer.verify(verifier)) {
                    throw new SignatureException("Signature does not match");
                }
            }
        } catch (final CMSException | OperatorCreationException | CertificateException e) {
            throw new SignatureException("Invalid CMS signature: " + e.getMessage());
        }
    }

    /**
     * @param signature a signature element from the ToC
     * @return the binary data representing the signature
     * @throws IOException when there is an error while reading the signature from the source xar
     */
    private ByteString readStoredSignature(final Signature signature) throws IOException {
        try (final BufferedSource sigSource = xarSource.getRange(baseOffset + signature.getOffset(), signature.getSize())) {
            return sigSource.readByteString(signature.getSize());
        }
    }

    /**
     * @param signature a signature element from the ToC
     * @return a X.509 certificate corresponding with the signature
     * @throws CertificateException when there is an error while extracting the certificate
     * @throws SignatureException when there is an error while reading the signature
     */
    private X509Certificate loadCertificate(final Signature signature)
        throws CertificateException, SignatureException
    {
        return loadCertificate(signature, null);
    }

    /**
     * @param signature a signature element from the ToC
     * @param encoding the encoding method for the signature
     * @return a X.509 certificate corresponding with the signature
     * @throws CertificateException when there is an error while extracting the certificate
     * @throws SignatureException when there is an error while reading the signature
     */
    private X509Certificate loadCertificate(final Signature signature, final String encoding)
        throws CertificateException, SignatureException
    {
        if (signature.getKeyInfo().getCertificates().isEmpty()) {
            throw new CertificateException("No certificates found to perform the signature check with");
        }

        if (encoding != null && !signature.getStyle().equals(encoding)) {
            throw new SignatureException("Expected a " + encoding + " signature");
        }

        return convertToX509Certificate(signature.getKeyInfo().getCertificates().get(0));
    }

    /**
     * Verifies the integrity of the source's ToC
     *
     * @param toc the {@link XarToc} to verify
     * @throws XarException when the stored checksum does not match the calculated checksum
     */
    private void verifyChecksum(final XarToc toc) throws XarException {
        final ByteString storedChecksum = xarSource.getStoredChecksum();

        // Determine if the stored checksum matches the actual ToC checksum
        try {
            final ByteString calculatedChecksum = toc.getCalculatedChecksum();

            if (calculatedChecksum == null) {
                throw new IllegalStateException("ToC checksum could not be calculated");
            }
            if (!calculatedChecksum.equals(storedChecksum)) {
                throw new IOException("Checksum error on the ToC header");
            }
        } catch (final IOException | IllegalStateException e) {
            throw new XarException("Invalid ToC checksum encountered", e);
        }
    }

    /**
     * @param base64Cert base64-encoded certificate data
     * @return a X.509 certificate
     * @throws CertificateException when the certificate data could not be converted into a X.509 certificate
     */
    private X509Certificate convertToX509Certificate(final String base64Cert) throws CertificateException {
        final CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");

        final ByteString decodedCert = ByteString.decodeBase64(base64Cert);
        if (decodedCert == null) {
            throw new CertificateException("Invalid base64-encoded certificate data encountered");
        }

        final InputStream in = new ByteArrayInputStream(decodedCert.toByteArray());
        return (X509Certificate) certificateFactory.generateCertificate(in);
    }
}
