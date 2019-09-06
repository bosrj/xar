package com.sprylab.xar.toc.model;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.stream.Collectors;

import org.apache.commons.codec.binary.Base64;
import org.simpleframework.xml.ElementList;
import org.simpleframework.xml.Namespace;
import org.simpleframework.xml.Root;

@Root(name = "KeyInfo")
@Namespace(reference = "http://www.w3.org/2000/09/xmldsig#")
public class KeyInfo {
    public static String serializeCert(final X509Certificate cert) {
        try {
            final Base64 encoder = new Base64(76);
            return new String(encoder.encode(cert.getEncoded()));
        } catch (CertificateEncodingException e) {
            throw new RuntimeException(e);
        }
    }

    @ElementList(name = "X509Data", entry = "X509Certificate")
    private List<String> certificates;

    public KeyInfo() {
    }

    public KeyInfo(final List<X509Certificate> certificateChain) {
        certificates = certificateChain.stream().map(KeyInfo::serializeCert).collect(Collectors.toList());
    }

    public List<String> getCertificates() {
        return certificates;
    }
}