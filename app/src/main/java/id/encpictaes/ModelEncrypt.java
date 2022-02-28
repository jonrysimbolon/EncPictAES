package id.encpictaes;

public class ModelEncrypt{
    private String[][] encrypt;
    private String[][] key;

    public ModelEncrypt(String[][] encrypt, String[][] key) {
        this.encrypt = encrypt;
        this.key = key;
    }

    public String[][] getEncrypt() {
        return encrypt;
    }

    public void setEncrypt(String[][] encrypt) {
        this.encrypt = encrypt;
    }

    public String[][] getKey() {
        return key;
    }

    public void setKey(String[][] key) {
        this.key = key;
    }
}
