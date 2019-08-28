package com.sprylab.xar.toc.model;

import java.security.cert.X509Certificate;
import java.util.List;

import org.simpleframework.xml.Attribute;
import org.simpleframework.xml.Element;
import org.simpleframework.xml.Root;

@Root
public class Signature {
    @Attribute
    private String style;

    @Element
    private int offset;

    @Element
    private int size;

    @Element(name = "KeyInfo")
    private KeyInfo keyInfo;

    public Signature() {
    }

    public Signature(final List<X509Certificate> certificateChain, final String style, final int offset, final int size) {
        this.style = style;
        this.offset = offset;
        this.size = size;
        keyInfo = new KeyInfo(certificateChain);
    }

    public String getStyle() {
        return style;
    }

    public int getOffset() {
        return offset;
    }

    public int getSize() {
        return size;
    }

    public KeyInfo getKeyInfo() {
        return keyInfo;
    }
}
