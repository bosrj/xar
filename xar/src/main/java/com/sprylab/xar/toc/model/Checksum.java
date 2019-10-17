package com.sprylab.xar.toc.model;

import org.simpleframework.xml.Attribute;
import org.simpleframework.xml.Element;
import org.simpleframework.xml.Root;

@Root
public class Checksum {

    private ChecksumAlgorithm style;

    private long size;

    private long offset;

    public Checksum(@Attribute(name = "style") final String style,
                    @Element(name = "size") final long size,
                    @Element(name = "offset") final long offset) {
        this(ChecksumAlgorithm.valueOf(style.toUpperCase()), size, offset);
    }

    public Checksum(final ChecksumAlgorithm style,
                    final long size,
                    final long offset) {
        this.style = style;
        this.size = size;
        this.offset = offset;
    }

    @Attribute(name = "style")
    public String getStyleRaw() {
        return style.name().toLowerCase();
    }

    public ChecksumAlgorithm getStyle() {
        return style;
    }

    public void setStyle(final ChecksumAlgorithm style) {
        this.style = style;
    }

    @Element(name = "size")
    public long getSize() {
        return size;
    }

    public void setSize(final long size) {
        this.size = size;
    }

    @Element(name = "offset")
    public long getOffset() {
        return offset;
    }

    public void setOffset(final long offset) {
        this.offset = offset;
    }
}
