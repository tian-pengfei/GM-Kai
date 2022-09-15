package net.gmkai.crypto;

public enum MacAlg {

    M_SM3("SM3", 32),

    M_SHA256("SHA256", 32);

    private final String name;

    private final int macLength;

    MacAlg(String name, int macLength) {
        this.name = name;
        this.macLength = macLength;
    }

    public String getName() {
        return name;
    }

    public int getMacLength() {
        return macLength;
    }
}