package id.encpictaes;

public class ModelDecrypt {
    private String[][] decrypt;
    private String[][] key;

    public String[][] getDecrypt() {
        return decrypt;
    }

    public void setDecrypt(String[][] decrypt) {
        this.decrypt = decrypt;
    }

    public String[][] getKey() {
        return key;
    }

    public void setKey(String[][] key) {
        this.key = key;
    }

    public ModelDecrypt(String[][] decrypt, String[][] key) {
        this.decrypt = decrypt;
        this.key = key;
    }
}
