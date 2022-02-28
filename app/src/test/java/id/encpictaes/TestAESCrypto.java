package id.encpictaes;

import org.junit.Test;

import java.util.Arrays;

public class TestAESCrypto {
    @Test
    public void Test() {

        AESCryptCustom aesCrypto = new AESCryptCustom();

        /*ModelEncrypt encryptInfo = aesCrypto.encrypt("SitiFatimahPunya","IniBerkasPenting");

        System.out.println("ENCRYPT DARI DEPAN : "+ Arrays.deepToString(encryptInfo.getEncrypt()));
        System.out.println("KEY DARI DEPAN : "+Arrays.deepToString(encryptInfo.getKey()));*/

        //encrypt = [[e8, c8, 17, 84], [2e, 78, ea, 57], [96, 7c, f1, 89], [2a, aa, a2, 33]]
        //key = [[13, c6, d0, 46], [1a, e8, c1, 57], [2, 73, c1, f3], [1b, 29, a8, d3]]

        System.out.println("");

        String[][] encryptArr = new String[][]{
                {
                        "e8", "c8", "17", "84"
                },
                {
                        "2e", "78", "ea", "57"
                },
                {
                        "96", "7c", "f1", "89"
                },
                {
                        "2a", "aa", "a2", "33"
                },
        };

        String[][] keyArr = new String[][]{
                {
                        "13", "c6", "d0", "46"
                },
                {
                        "1a", "e8", "c1", "57"
                },
                {
                        "2", "73", "c1", "f3"
                },
                {
                        "1b", "29", "a8", "d3"
                },
        };

        ModelDecrypt decrypteInfo = aesCrypto.decrypt(encryptArr, keyArr);
        System.out.println("DECRYPT DARI DEPAN : " + Arrays.deepToString(decrypteInfo.getDecrypt()));
        System.out.println("KEY DARI DEPAN : " + Arrays.deepToString(decrypteInfo.getKey()));

    }
}
