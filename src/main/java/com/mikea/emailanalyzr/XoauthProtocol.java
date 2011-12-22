package com.mikea.emailanalyzr;

/**
 * Represents a protocol that can be authenticated with XOAUTH.
 */
public enum XoauthProtocol {
    IMAP("imap"),
    SMTP("smtp");

    private final String name;

    XoauthProtocol(String name) {
        this.name = name;
    }

    /**
     * Returns the protocol name to be embedded in the XOAUTH URL.
     */
    public String getName() {
        return name;
    }
}