package net.gmkai.crypto;

public enum HashAlg {
    H_SM3("SM3"),

    H_SHA256("SHA256");

    private final String name;


    HashAlg(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }

}
