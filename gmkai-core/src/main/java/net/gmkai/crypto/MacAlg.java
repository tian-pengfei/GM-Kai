package net.gmkai.crypto;

public enum MacAlg {
    M_SM3("SM3"),

    M_SHA256("SHA256");

    private final String name;


    MacAlg(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }
}