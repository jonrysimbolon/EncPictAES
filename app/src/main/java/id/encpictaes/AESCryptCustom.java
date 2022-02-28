package id.encpictaes;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Collections;

public class AESCryptCustom {

    String[][] rcon = new String[][]{
            {"01", "02", "04", "08", "10", "20", "40", "80", "1B", "36"},
            {"00", "00", "00", "00", "00", "00", "00", "00", "00", "00"},
            {"00", "00", "00", "00", "00", "00", "00", "00", "00", "00"},
            {"00", "00", "00", "00", "00", "00", "00", "00", "00", "00"}
    }; //nilai rcon


    String[][] mcMtx = new String[][]{
            {"02", "03", "01", "01"},
            {"01", "02", "03", "01"},
            {"01", "01", "02", "03"},
            {"03", "01", "01", "02"}
    }; //nilai rcon


    String[][] box = {
            {"63", "7c", "77", "7b", "f2", "6b", "6f", "c5", "30", "01", "67", "2b", "fe", "d7", "ab", "76"},
            {"ca", "82", "c9", "7d", "fa", "59", "47", "f0", "ad", "d4", "a2", "af", "9c", "a4", "72", "c0"},
            {"b7", "fd", "93", "26", "36", "3f", "f7", "cc", "34", "a5", "e5", "f1", "71", "d8", "31", "15"},
            {"04", "c7", "23", "c3", "18", "96", "05", "9a", "07", "12", "80", "e2", "eb", "27", "b2", "75"},
            {"09", "83", "2c", "1a", "1b", "6e", "5a", "a0", "52", "3b", "d6", "b3", "29", "e3", "2f", "84"},
            {"53", "d1", "00", "ed", "20", "fc", "b1", "5b", "6a", "cb", "be", "39", "4a", "4c", "58", "cf"},
            {"d0", "ef", "aa", "fb", "43", "4d", "33", "85", "45", "f9", "02", "7f", "50", "3c", "9f", "a8"},
            {"51", "a3", "40", "8f", "92", "9d", "38", "f5", "bc", "b6", "da", "21", "10", "ff", "f3", "d2"},
            {"cd", "0c", "13", "ec", "5f", "97", "44", "17", "c4", "a7", "7e", "3d", "64", "5d", "19", "73"},
            {"60", "81", "4f", "dc", "22", "2a", "90", "88", "46", "ee", "b8", "14", "de", "5e", "0b", "db"},
            {"e0", "32", "3a", "0a", "49", "06", "24", "5c", "c2", "d3", "ac", "62", "91", "95", "e4", "79"},
            {"e7", "c8", "37", "6d", "8d", "d5", "4e", "a9", "6c", "56", "f4", "ea", "65", "7a", "ae", "08"},
            {"ba", "78", "25", "2e", "1c", "a6", "b4", "c6", "e8", "dd", "74", "1f", "4b", "bd", "8b", "8a"},
            {"70", "3e", "b5", "66", "48", "03", "f6", "0e", "61", "35", "57", "b9", "86", "c1", "1d", "9e"},
            {"e1", "f8", "98", "11", "69", "d9", "8e", "94", "9b", "1e", "87", "e9", "ce", "55", "28", "df"},
            {"8c", "a1", "89", "0d", "bf", "e6", "42", "68", "41", "99", "2d", "0f", "b0", "54", "bb", "16"}
    };
    String[][] invBox = {
            {"52", "09", "6a", "d5", "30", "36", "a5", "38", "bf", "40", "a3", "9e", "81", "f3", "d7", "fb"},
            {"7c", "e3", "39", "82", "9b", "2f", "ff", "87", "34", "8e", "43", "44", "c4", "de", "e9", "cb"},
            {"54", "7b", "94", "32", "a6", "c2", "23", "3d", "ee", "4c", "95", "0b", "42", "fa", "c3", "4e"},
            {"08", "2e", "a1", "66", "28", "d9", "24", "b2", "76", "5b", "a2", "49", "6d", "8b", "d1", "25"},
            {"72", "f8", "f6", "64", "86", "68", "98", "16", "d4", "a4", "5c", "cc", "5d", "65", "b6", "92"},
            {"6c", "70", "48", "50", "fd", "ed", "b9", "da", "5e", "15", "46", "57", "a7", "8d", "9d", "84"},
            {"90", "d8", "ab", "00", "8c", "bc", "d3", "0a", "f7", "e4", "58", "05", "b8", "b3", "45", "06"},
            {"d0", "2c", "1e", "8f", "ca", "3f", "0f", "02", "c1", "af", "bd", "03", "01", "13", "8a", "6b"},
            {"3a", "91", "11", "41", "4f", "67", "dc", "ea", "97", "f2", "cf", "ce", "f0", "b4", "e6", "73"},
            {"96", "ac", "74", "22", "e7", "ad", "35", "85", "e2", "f9", "37", "e8", "1c", "75", "df", "6e"},
            {"47", "f1", "1a", "71", "1d", "29", "c5", "89", "6f", "b7", "62", "0e", "aa", "18", "be", "1b"},
            {"fc", "56", "3e", "4b", "c6", "d2", "79", "20", "9a", "db", "c0", "fe", "78", "cd", "5a", "f4"},
            {"1f", "dd", "a8", "33", "88", "07", "c7", "31", "b1", "12", "10", "59", "27", "80", "ec", "5f"},
            {"60", "51", "7f", "a9", "19", "b5", "4a", "0d", "2d", "e5", "7a", "9f", "93", "c9", "9c", "ef"},
            {"a0", "e0", "3b", "4d", "ae", "2a", "f5", "b0", "c8", "eb", "bb", "3c", "83", "53", "99", "61"},
            {"17", "2b", "04", "7e", "ba", "77", "d6", "26", "e1", "69", "14", "63", "55", "21", "0c", "7d"}
    };

    public AESCryptCustom() {

    }

    public ModelDecrypt decrypt(String[][] encArr, String[][] keyArr) {

        String[][] keySchedule10 = KeySchedule(keyArr, 1); // for key 1
        String[][] decryptionProcess10 = DecryptionProcess10(encArr); // for text 10

        return new ModelDecrypt(encArr,keyArr);
    }

    public ModelEncrypt encrypt(String key, String text) {

        System.out.println("===========================================================================================");
        System.out.println("");

        System.out.println("===========================================================================================");
        System.out.println("");
        System.out.println("Key : " + key);
        System.out.println("Text : " + text);

        System.out.println("===========================================================================================");
        System.out.println("");

        String keyByte = toHex(key);
        String textByte = toHex(text);

        String[] keyArr = new String[16];
        String[] textArr = new String[16];

        int j = 0;
        for (int i = 0; i < 32; i += 2) { //32 digit
            String subKey = keyByte.substring(i, i + 2);
            keyArr[j] = subKey;

            String subText = textByte.substring(i, i + 2);
            textArr[j] = subText;

            j++;
        }

        System.out.println("Key : " + Arrays.toString(keyArr));
        System.out.println("Text : " + Arrays.toString(textArr));

        String[][] keyArr2d = new String[4][4];
        String[][] textArr2d = new String[4][4];

        int c = 0;
        for (int a = 0; a < keyArr2d.length; a++) { // baris
            for (int b = 0; b < keyArr2d.length; b++) { // kolom
                keyArr2d[b][a] = keyArr[c];
                textArr2d[b][a] = textArr[c];
                c++;
            }
        }

        System.out.println("===========================================================================================");
        System.out.println("");


        //===========================================================================================
        //xor enc round 1

        String[][] keySchedule = KeySchedule(keyArr2d, 1); // for key 1
        String[][] encryptionProcess = EncryptionProcess(textArr2d, keyArr2d); // for text 1

        printlnn("keySchedule : " + Arrays.deepToString(keySchedule));
        printlnn("Encription process : " + Arrays.deepToString(encryptionProcess));

        printlnn("");
        printlnn("");

        System.out.println("Key 1 : " + Arrays.deepToString(keySchedule));
        System.out.println("Text 1 : " + Arrays.deepToString(encryptionProcess));

        String[][] xorKeyEnc1 = new String[4][4];
        for (int i = 0; i < keySchedule.length; i++) {
            for (int k = 0; k < encryptionProcess.length; k++) {
                String x = totalXOR(convertArr(hexToBin(keySchedule[i][k]), 8), convertArr(hexToBin(encryptionProcess[i][k]), 8));
                //printlnn(i+" + "+k+" : "+x);
                xorKeyEnc1[i][k] = binToHex(arrToStr(x));
            }
        }
        printlnn("");
        printlnn("Xor Enc Key 1 : " + Arrays.deepToString(xorKeyEnc1));
        printlnn("Key Schedule 1 : " + Arrays.deepToString(keySchedule));


        //===========================================================================================
        //xor enc round 2

        String[][] keySchedule2 = KeySchedule(keySchedule, 2); // for key 2
        String[][] encryptionProcess2 = EncryptionProcess2(xorKeyEnc1); // for text 2

        String[][] xorKeyEnc2 = new String[4][4];
        for (int i = 0; i < keySchedule2.length; i++) {
            for (int k = 0; k < encryptionProcess2.length; k++) {
                String x = totalXOR(convertArr(hexToBin(keySchedule2[i][k]), 8), convertArr(hexToBin(encryptionProcess2[i][k]), 8));
                //printlnn(i+" + "+k+" : "+x);
                xorKeyEnc2[i][k] = binToHex(arrToStr(x));
            }
        }
        printlnn("");
        printlnn("Xor Enc Key 2 : " + Arrays.deepToString(xorKeyEnc2));
        printlnn("Key Schedule 2 : " + Arrays.deepToString(keySchedule2));


        //===========================================================================================
        //xor enc round 3

        String[][] keySchedule3 = KeySchedule(keySchedule2, 3); // for key 3
        String[][] encryptionProcess3 = EncryptionProcess2(xorKeyEnc2); // for text 3

        String[][] xorKeyEnc3 = new String[4][4];
        for (int i = 0; i < keySchedule3.length; i++) {
            for (int k = 0; k < encryptionProcess3.length; k++) {
                String x = totalXOR(convertArr(hexToBin(keySchedule3[i][k]), 8), convertArr(hexToBin(encryptionProcess3[i][k]), 8));
                //printlnn(i+" + "+k+" : "+x);
                xorKeyEnc3[i][k] = binToHex(arrToStr(x));
            }
        }
        printlnn("");
        printlnn("Xor Enc Key 3 : " + Arrays.deepToString(xorKeyEnc3));
        printlnn("Key Schedule 3 : " + Arrays.deepToString(keySchedule3));

        //===========================================================================================
        //xor enc round 4

        String[][] keySchedule4 = KeySchedule(keySchedule3, 4); // for key 4
        String[][] encryptionProcess4 = EncryptionProcess2(xorKeyEnc3); // for text 4

        String[][] xorKeyEnc4 = new String[4][4];
        for (int i = 0; i < keySchedule4.length; i++) {
            for (int k = 0; k < encryptionProcess4.length; k++) {
                String x = totalXOR(convertArr(hexToBin(keySchedule4[i][k]), 8), convertArr(hexToBin(encryptionProcess4[i][k]), 8));
                //printlnn(i+" + "+k+" : "+x);
                xorKeyEnc4[i][k] = binToHex(arrToStr(x));
            }
        }
        printlnn("");
        printlnn("Xor Enc Key 4 : " + Arrays.deepToString(xorKeyEnc4));
        printlnn("Key Schedule 4 : " + Arrays.deepToString(keySchedule4));

        //===========================================================================================
        //xor enc round 5

        String[][] keySchedule5 = KeySchedule(keySchedule4, 5); // for key 5
        String[][] encryptionProcess5 = EncryptionProcess2(xorKeyEnc4); // for text 5

        String[][] xorKeyEnc5 = new String[4][4];
        for (int i = 0; i < keySchedule5.length; i++) {
            for (int k = 0; k < encryptionProcess5.length; k++) {
                String x = totalXOR(convertArr(hexToBin(keySchedule5[i][k]), 8), convertArr(hexToBin(encryptionProcess5[i][k]), 8));
                //printlnn(i+" + "+k+" : "+x);
                xorKeyEnc5[i][k] = binToHex(arrToStr(x));
            }
        }
        printlnn("");
        printlnn("Xor Enc Key 5 : " + Arrays.deepToString(xorKeyEnc5));
        printlnn("Key Schedule 5 : " + Arrays.deepToString(keySchedule5));

        System.out.println("===========================================================================================");
        System.out.println("");

        //===========================================================================================
        //xor enc round 6

        String[][] keySchedule6 = KeySchedule(keySchedule5, 6); // for key 6
        String[][] encryptionProcess6 = EncryptionProcess2(xorKeyEnc5); // for text 6

        String[][] xorKeyEnc6 = new String[4][4];
        for (int i = 0; i < keySchedule6.length; i++) {
            for (int k = 0; k < encryptionProcess6.length; k++) {
                String x = totalXOR(convertArr(hexToBin(keySchedule6[i][k]), 8), convertArr(hexToBin(encryptionProcess6[i][k]), 8));
                //printlnn(i+" + "+k+" : "+x);
                xorKeyEnc6[i][k] = binToHex(arrToStr(x));
            }
        }
        printlnn("");
        printlnn("Xor Enc Key 6 : " + Arrays.deepToString(xorKeyEnc6));
        printlnn("Key Schedule 6 : " + Arrays.deepToString(keySchedule6));

        //===========================================================================================
        //xor enc round 7

        String[][] keySchedule7 = KeySchedule(keySchedule6, 7); // for key 7
        String[][] encryptionProcess7 = EncryptionProcess2(xorKeyEnc6); // for text 7

        String[][] xorKeyEnc7 = new String[4][4];
        for (int i = 0; i < keySchedule7.length; i++) {
            for (int k = 0; k < encryptionProcess7.length; k++) {
                String x = totalXOR(convertArr(hexToBin(keySchedule7[i][k]), 8), convertArr(hexToBin(encryptionProcess7[i][k]), 8));
                //printlnn(i+" + "+k+" : "+x);
                xorKeyEnc7[i][k] = binToHex(arrToStr(x));
            }
        }
        printlnn("");
        printlnn("Xor Enc Key 7 : " + Arrays.deepToString(xorKeyEnc7));
        printlnn("Key Schedule 7 : " + Arrays.deepToString(keySchedule7));

        //===========================================================================================
        //xor enc round 8

        String[][] keySchedule8 = KeySchedule(keySchedule7, 8); // for key 8
        String[][] encryptionProcess8 = EncryptionProcess2(xorKeyEnc7); // for text 8

        String[][] xorKeyEnc8 = new String[4][4];
        for (int i = 0; i < keySchedule8.length; i++) {
            for (int k = 0; k < encryptionProcess8.length; k++) {
                String x = totalXOR(convertArr(hexToBin(keySchedule8[i][k]), 8), convertArr(hexToBin(encryptionProcess8[i][k]), 8));
                //printlnn(i+" + "+k+" : "+x);
                xorKeyEnc8[i][k] = binToHex(arrToStr(x));
            }
        }
        printlnn("");
        printlnn("Xor Enc Key 8 : " + Arrays.deepToString(xorKeyEnc8));
        printlnn("Key Schedule 8 : " + Arrays.deepToString(keySchedule8));

        //===========================================================================================
        //xor enc round 9

        String[][] keySchedule9 = KeySchedule(keySchedule8, 9); // for key 9
        String[][] encryptionProcess9 = EncryptionProcess2(xorKeyEnc8); // for text 9

        String[][] xorKeyEnc9 = new String[4][4];
        for (int i = 0; i < keySchedule9.length; i++) {
            for (int k = 0; k < encryptionProcess9.length; k++) {
                String x = totalXOR(convertArr(hexToBin(keySchedule9[i][k]), 8), convertArr(hexToBin(encryptionProcess9[i][k]), 8));
                //printlnn(i+" + "+k+" : "+x);
                xorKeyEnc9[i][k] = binToHex(arrToStr(x));
            }
        }
        printlnn("");
        printlnn("Xor Enc Key 9 : " + Arrays.deepToString(xorKeyEnc9));
        printlnn("Key Schedule 9 : " + Arrays.deepToString(keySchedule9));

        System.out.println("===========================================================================================");
        System.out.println("");

        //===========================================================================================
        //xor enc round 10

        String[][] keySchedule10 = KeySchedule(keySchedule9, 10); // for key 10
        String[][] encryptionProcess10 = EncryptionProcess10(xorKeyEnc8); // for text 10

        String[][] xorKeyEnc10 = new String[4][4];
        for (int i = 0; i < keySchedule10.length; i++) {
            for (int k = 0; k < encryptionProcess10.length; k++) {
                String x = totalXOR(convertArr(hexToBin(keySchedule10[i][k]), 8), convertArr(hexToBin(encryptionProcess10[i][k]), 8));
                //printlnn(i+" + "+k+" : "+x);
                xorKeyEnc10[i][k] = binToHex(arrToStr(x));
            }
        }
        printlnn("");
        printlnn("Xor Enc Key 10 : " + Arrays.deepToString(xorKeyEnc10));
        printlnn("Key Schedule 10 : " + Arrays.deepToString(keySchedule10));

        System.out.println("===========================================================================================");
        System.out.println("");

        return new ModelEncrypt(xorKeyEnc10,keySchedule10);
    }

    private String[][] EncryptionProcess10(String[][] textArr2d){//tanpa mixColumn
     /*printlnn("=============================================================");
        printlnn("EncryptionProcess");
        printlnn("=============================================================");
        printlnn("");
        printlnn("");*/

        String[][] awlAndSbyt = new String[4][4];

        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                String text0 = hexToBin(textArr2d[i][j]);
                //System.out.println(text0);

                //convert binary jadi sama panjangnya
                String cvt = convertArr(text0, 8);

                String hxtk0 = binToHex(arrToStr(cvt));

                if (hxtk0.length() != 2) {
                    hxtk0 = "0" + hxtk0;
                }

                //subtype sbox
                String[] pch44 = hxtk0.split("");
                String h4b4 = box[ConvertStringToInt(pch44[0])][ConvertStringToInt(pch44[1])];

                awlAndSbyt[i][j] = h4b4;
            }
        }

        /*printlnn("");*/
        printlnn("");
        System.out.println("awal subtitusi 2 : " + Arrays.deepToString(awlAndSbyt));
        printlnn("");
        /*printlnn("");*/

        //==================================================
        //shiftrow

        String[][] srCpt = new String[4][4];

        int l;
        for (int i = 0; i < 4; i++) {
            l = i;
            for (int j = 0; j < 4; j++) {
                if (l == 4) {
                    l = 0;
                }
                //System.out.println("["+i+"]["+j+"] = "+"["+i+"]"+"["+l+"]");
                srCpt[i][j] = awlAndSbyt[i][l];
                l++;
            }
            //System.out.println();
        }

        /*printlnn("");*/
        printlnn("");
        System.out.println("srcpt shiftrows : " + Arrays.deepToString(srCpt));
        printlnn("");
        /*printlnn("");*/

        //==================================================

        //mixcolumn

        /*String[][] mixClm = new String[4][4];

        for (int i = 0; i < mixClm.length; i++) {
            for (int j = 0; j < mixClm.length; j++) {
                String dtMix = prklDot0(srCpt, mcMtx, j, i); //after mix column 30
                //printlnn("dtMix : " + dtMix);
                mixClm[j][i] = dtMix;
            }
        }

        printlnn("");
        //printlnn("=================================");
        printlnn("mixClm : " + Arrays.deepToString(mixClm));
        //printlnn("=================================");
        printlnn("");*/

        return srCpt;
    }

    private String[][] DecryptionProcess10(String[][] encArr){//tanpa mixColumn

        String[][] srCpt = new String[4][4];

        int l;
        for (int i = 0; i < 4; i++) {
            l = i;
            for (int j = 0; j < 4; j++) {
                if (l == 4) {
                    l = 0;
                }
                //System.out.println("["+i+"]["+l+"] = "+"["+i+"]"+"["+j+"]");
                srCpt[i][l] = encArr[i][j];
                l++;
            }
            //System.out.println();
        }

        /*printlnn("");*/
        printlnn("");
        System.out.println("srcpt INV shiftrows : " + Arrays.deepToString(srCpt));
        printlnn("");

        String[][] awlAndSbyt = new String[4][4];

        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                String text0 = hexToBin(srCpt[i][j]);
                //System.out.println(text0);

                //convert binary jadi sama panjangnya
                String cvt = convertArr(text0, 8);

                String hxtk0 = binToHex(arrToStr(cvt));

                if (hxtk0.length() != 2) {
                    hxtk0 = "0" + hxtk0;
                }

                //subtype sbox
                String[] pch44 = hxtk0.split("");
                String h4b4 = invBox[ConvertStringToInt(pch44[0])][ConvertStringToInt(pch44[1])];

                awlAndSbyt[i][j] = h4b4;
            }
        }

        /*printlnn("");*/
        printlnn("");
        System.out.println("INV subtitusi  : " + Arrays.deepToString(awlAndSbyt));
        printlnn("");

        return srCpt;
    }

    private String[][] EncryptionProcess2(String[][] textArr2d) {
        /*printlnn("=============================================================");
        printlnn("EncryptionProcess");
        printlnn("=============================================================");
        printlnn("");
        printlnn("");*/

        String[][] awlAndSbyt = new String[4][4];

        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                String text0 = hexToBin(textArr2d[i][j]);
                //System.out.println(text0);

                //convert binary jadi sama panjangnya
                String cvt = convertArr(text0, 8);

                String hxtk0 = binToHex(arrToStr(cvt));

                if (hxtk0.length() != 2) {
                    hxtk0 = "0" + hxtk0;
                }

                //subtype sbox
                String[] pch44 = hxtk0.split("");
                String h4b4 = box[ConvertStringToInt(pch44[0])][ConvertStringToInt(pch44[1])];

                awlAndSbyt[i][j] = h4b4;
            }
        }

        /*printlnn("");*/
        printlnn("");
        System.out.println("awal subtitusi 2 : " + Arrays.deepToString(awlAndSbyt));
        printlnn("");
        /*printlnn("");*/

        //==================================================
        //shiftrow

        String[][] srCpt = new String[4][4];

        int l;
        for (int i = 0; i < 4; i++) {
            l = i;
            for (int j = 0; j < 4; j++) {
                if (l == 4) {
                    l = 0;
                }
                //System.out.println("["+i+"]["+j+"] = "+"["+i+"]"+"["+l+"]");
                srCpt[i][j] = awlAndSbyt[i][l];
                l++;
            }
            //System.out.println();
        }

        /*printlnn("");*/
        printlnn("");
        System.out.println("srcpt shiftrows : " + Arrays.deepToString(srCpt));
        printlnn("");
        /*printlnn("");*/

        //==================================================

        //mixcolumn

        String[][] mixClm = new String[4][4];

        for (int i = 0; i < mixClm.length; i++) {
            for (int j = 0; j < mixClm.length; j++) {
                String dtMix = prklDot0(srCpt, mcMtx, j, i); //after mix column 30
                //printlnn("dtMix : " + dtMix);
                mixClm[j][i] = dtMix;
            }
        }

        printlnn("");
        //printlnn("=================================");
        printlnn("mixClm : " + Arrays.deepToString(mixClm));
        //printlnn("=================================");
        printlnn("");

        return mixClm;
    }

    private String[][] EncryptionProcess(String[][] textArr2d, String[][] keyArr2d) {

        /*printlnn("=============================================================");
        printlnn("EncryptionProcess");
        printlnn("=============================================================");
        printlnn("");
        printlnn("");*/

        String[][] awlAndSbyt = new String[4][4];

        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                String text0 = hexToBin(textArr2d[i][j]);
                //System.out.println(text0);

                String key0 = hexToBin(keyArr2d[i][j]);
                //System.out.println(key0);

                //check length
                int panjangArr4 = check2Length(text0, key0);

                //convert binary jadi sama panjangnya
                String cvt = convertArr(text0, panjangArr4);
                String cvk = convertArr(key0, panjangArr4);

                String tk0 = totalXOR(cvt, cvk);
                String hxtk0 = binToHex(arrToStr(tk0));

                if (hxtk0.length() != 2) {
                    hxtk0 = "0" + hxtk0;
                }

                //subtype sbox
                String[] pch44 = hxtk0.split("");
                String h4b4 = box[ConvertStringToInt(pch44[0])][ConvertStringToInt(pch44[1])];

                awlAndSbyt[i][j] = h4b4;
            }
        }

        /*printlnn("");*/
        printlnn("");
        System.out.println("awal subtitusi 1 : " + Arrays.deepToString(awlAndSbyt));
        printlnn("");
        /*printlnn("");*/

        //==================================================
        //shiftrow

        String[][] srCpt = new String[4][4];

        int l;
        for (int i = 0; i < 4; i++) {
            l = i;
            for (int j = 0; j < 4; j++) {
                if (l == 4) {
                    l = 0;
                }
                //System.out.println("["+i+"]["+j+"] = "+"["+i+"]"+"["+l+"]");
                srCpt[i][j] = awlAndSbyt[i][l];
                l++;
            }
            //System.out.println();
        }

        /*printlnn("");*/
        printlnn("");
        System.out.println("srcpt shiftrows : " + Arrays.deepToString(srCpt));
        printlnn("");
        /*printlnn("");*/

        //==================================================

        //mixcolumn

        String[][] mixClm = new String[4][4];

        for (int i = 0; i < mixClm.length; i++) {
            for (int j = 0; j < mixClm.length; j++) {
                String dtMix = prklDot0(srCpt, mcMtx, j, i); //after mix column 30
                //printlnn("dtMix : " + dtMix);
                mixClm[j][i] = dtMix;
            }
        }

        printlnn("");
        //printlnn("=================================");
        printlnn("mixClm : " + Arrays.deepToString(mixClm));
        //printlnn("=================================");
        printlnn("");

        return mixClm;
    }

    private String prklDot0(String[][] srCpt, String[][] mcMtx, int pertama, int kedua) {
        String ttlXor = "";
        for (int i = 0; i < 4; i++) {
            String mxClmn = mixColumn1(srCpt[i][kedua], mcMtx[pertama][i]);
            //printlnn("mxClmn : " + mxClmn);
            if (i != 0) {
                //printlnn("" + i + "");
                ttlXor = arrToStr(totalXOR(ttlXor, mxClmn));
            } else {
                ttlXor = mxClmn;
            }
        }

        return binToHex(arrToStr(ttlXor));
    }

    private String mixColumn1(String srCpt0, String mcMtx0) {
        //ubah hex to binary

        /*printlnn("");
        printlnn("=============================================================");
        printlnn("mixColumn1");
        printlnn("=============================================================");*/

        /*printlnn("");
        printlnn("");
        printlnn("srcpt : " + srCpt0);
        printlnn("mcMtx : " + mcMtx0);*/

        String bmc0 = hexToBin(srCpt0);
        String mcc0 = hexToBin(mcMtx0);

        //int lgth0 = check2Length(bmc0, mcc0);

        //menormalkan panjang karakter agar sama dan bisa nantinya di XOR
        String bmcNor0 = convertArr(bmc0, 8);
        String mccNor0 = convertArr(mcc0, 8);

        /*printlnn("bmcnor 0 : " + bmcNor0);
        printlnn("mccNor 0 : " + mccNor0);*/

        String ciBmc0 = changeIndex(bmcNor0.split(""));
        String ciMcc0 = changeIndex(mccNor0.split("")); //dipastikan tidak ada x8 karna menurut table static maks 03

        /*printlnn("");
        printlnn("cibmc0 : " + ciBmc0);
        printlnn("ciMcc0 : " + ciMcc0);*/

        //perkalian

        return perkalianDot(ciBmc0, ciMcc0);
    }

    private String perkalianDot(String ciBmc0, String ciMcc0) {

        /*printlnn("");
        printlnn("=============================================================");
        printlnn("perkalianDot");
        printlnn("=============================================================");
        printlnn("");*/
        /*printlnn("cibmc0 : " + ciBmc0);
        printlnn("ciMcc0 : " + ciMcc0);
        printlnn("");*/

        String[] ciBox = ciBmc0.split("");
        int wdhNew;
        String wdhNewSmt = "";

        /*printlnn("ciBmc0 : " + ciBmc0);
        printlnn("ciBox : " + Arrays.toString(ciBox));
        printlnn("ciBox length : " + ciBox.length);*/

        if (!ciBox[0].equals("")) { //kalo cibox[0] == "", artinya didalam itu udah gk ada lagi apa-apa, pasti nilai dari after shiftrows nya ada yg 00
            if (ciMcc0.length() == 2) {//kalo yg dikalikan itu x+1, itu rumusnya beda lagi
                String[] mcArr = ciMcc0.split("");
                for (int i = 0; i < mcArr.length; i++) {
                    for (int j = 0; j < ciBox.length; j++) {
                        wdhNew = Integer.parseInt(ciBox[j]) + Integer.parseInt(mcArr[i]);
                        //printlnn("wdhnew " + i + " : " + wdhNew);
                        wdhNewSmt += String.valueOf(wdhNew);
                        //printlnn("wdhNewSmt " + i + " : " + wdhNewSmt);
                    }
                }
            } else {
                for (int i = 0; i < ciBox.length; i++) {
                    wdhNew = Integer.parseInt(ciBox[i]) + Integer.parseInt(ciMcc0);
                    //printlnn("wdhNew " + i + " : " + wdhNew);
                    wdhNewSmt += String.valueOf(wdhNew);
                    //printlnn("wdhNewSmt " + i + " : " + wdhNew);
                }
            }
        } else {
            wdhNew = 0;
            //printlnn("wdhNew " + 0 + " : " + wdhNew);
            wdhNewSmt += String.valueOf(wdhNew);
            //printlnn("wdhNewSmt " + 0 + " : " + wdhNew);
        }

        /*printlnn("");
        printlnn("=========================");
        printlnn("wdhNewSmt : " + wdhNewSmt);
        printlnn("=========================");
        printlnn("");*/


        //printlnn("Hapus nilai yg sama");

        //hapus nilai yg sama
        String[] wdhnssm = wdhNewSmt.split("");
        String nilaiSm = "";
        for (int i = 0; i < wdhnssm.length; i++) {
            for (int j = 0; j < wdhnssm.length; j++) {
                if (j != i) {
                    if (wdhnssm[i].equals(wdhnssm[j])) {
                        nilaiSm += wdhnssm[i];
                    }
                }
            }
        }
        //print nilai yg sama
        //printlnn("Nilai yg sama : " + nilaiSm);
        //replace dgn variable
        String[] nilSm = nilaiSm.split("");
        for (int i = 0; i < nilSm.length; i++) {
            wdhNewSmt = wdhNewSmt.replace(nilSm[i], "");
        }

        /*printlnn("wdhNewSmt : " + wdhNewSmt);
        printlnn("wdhNewSmt sudah hapus angka yg sama : " + wdhNewSmt);


        printlnn("Checking if ada 8");*/

        //checking.... if ada 8

        if (wdhNewSmt.contains("8")) {
            wdhNewSmt = wdhNewSmt.replace("8", "4310");

            //printlnn("Hapus nilai yg sama untuk ke 2 kalinya");
            //hapus nilai yg sama
            String[] wdhnssm2 = wdhNewSmt.split("");
            String nilaiSm2 = "";
            for (int i = 0; i < wdhnssm2.length; i++) {
                for (int j = 0; j < wdhnssm2.length; j++) {
                    if (j != i) {
                        if (wdhnssm2[i].equals(wdhnssm2[j])) {
                            nilaiSm2 += wdhnssm2[i];
                        }
                    }
                }
            }
            //print nilai yg sama
            //printlnn("Nilai yg sama untuk ke 2 kalinya : " + nilaiSm2);
            //replace dgn variable
            String[] nilSm2 = nilaiSm2.split("");
            for (int i = 0; i < nilSm2.length; i++) {
                wdhNewSmt = wdhNewSmt.replace(nilSm2[i], "");
            }

            /*printlnn("wdhNewSmt untuk ke 2 kalinya : " + wdhNewSmt);
            printlnn("wdhNewSmt sudah hapus angka yg sama untuk ke 2 kalinya : " + wdhNewSmt);*/

        }

        //printlnn("Atur tempat");
        String[] wdhNewSmt2 = wdhNewSmt.split("");
        Integer[] wdhNewSmt3 = new Integer[wdhNewSmt2.length];
        for (int i = 0; i < wdhNewSmt2.length; i++) {
            wdhNewSmt3[i] = Integer.parseInt(wdhNewSmt2[i]);
        }
        Arrays.sort(wdhNewSmt3, Collections.reverseOrder());
        //printlnn("wdhNewSmt3 : " + Arrays.toString(wdhNewSmt3));

        String[] binCust = new String[8];
        if (ciBox[0].equals("")) {
            binCust = new String[] {
                "0", "0", "0", "0", "0", "0", "0", "0"
            };
        } else {
            String wdNewSmt4 = Arrays.toString(wdhNewSmt3);
            int a = 7;
            for (int i = 0; i < binCust.length; i++) {
                if (wdNewSmt4.contains(String.valueOf(a))) {
                    binCust[i] = "1";
                } else {
                    binCust[i] = "0";
                }
                a--;
            }
        }

        /*printlnn("Bincust : " + Arrays.toString(binCust));
        printlnn("");*/

        return arrToStr(Arrays.toString(binCust));
    }

    private void printlnn(String text) {
        System.out.println(text);
    }

    private void printt(String text) {
        System.out.print(text);
    }

    private String[][] InvKeySchedule(String[][] keyArr2d10, int ke) {

        /*printlnn("");
        printlnn("=============================================================");
        printlnn("INV KeySchedule");
        printlnn("=============================================================");*/

        //LINE INV FOR ROUND 10
        String[][] keyArr2d210 = invMakeRound(10, keyArr2d10);

        return makeRound(ke, keyArr2d210);
    }

    private String[][] KeySchedule(String[][] keyArr2d, int ke) {

        /*printlnn("");
        printlnn("=============================================================");
        printlnn("KeySchedule");
        printlnn("=============================================================");
*/
        /*
        //LINE FOR ROUND 1
        String[][] keyArr2d21 = makeRound(1, keyArr2d);

        //LINE FOR ROUND 2
        String[][] keyArr2d22 = makeRound(2, keyArr2d21);

        //LINE FOR ROUND 3
        String[][] keyArr2d23 = makeRound(3, keyArr2d22);

        //LINE FOR ROUND 4
        String[][] keyArr2d24 = makeRound(4, keyArr2d23);

        //LINE FOR ROUND 5
        String[][] keyArr2d25 = makeRound(5, keyArr2d24);

        //LINE FOR ROUND 6
        String[][] keyArr2d26 = makeRound(6, keyArr2d25);

        //LINE FOR ROUND 7
        String[][] keyArr2d27 = makeRound(7, keyArr2d26);

        //LINE FOR ROUND 8
        String[][] keyArr2d28 = makeRound(8, keyArr2d27);

        //LINE FOR ROUND 9
        String[][] keyArr2d29 = makeRound(9, keyArr2d28);

        //LINE FOR ROUND 10
        String[][] keyArr2d210 = makeRound(10, keyArr2d29);*/


        /*System.out.println("");
        System.out.println("===========================================================================================");*/

        return makeRound(ke, keyArr2d);
    }

    private String[][] invMakeRound(int ke, String[][] keyArr2d2Sblm) {

        //=========================================   4   ==========================================
        //System.out.println();

        String c4b14 = keyArr2d2Sblm[1][3];
        //============================
        String c4b24 = keyArr2d2Sblm[2][3];
        //============================
        String c4b34 = keyArr2d2Sblm[3][3];
        //============================
        String c4b44 = keyArr2d2Sblm[0][3];
        //============================

        //input data diatas dalam 1 var array
        String[] convKeyArrb4 = {c4b14, c4b24, c4b34, c4b44};

        //LINE FOR ROUND 4
        String[][] keyArr2d24 = new String[4][4]; //buat array baru untuk round 1

        //blok 1 perulangan 4 kali
        for (int h = 0; h < 4; h++) {
            keyArr2d24[h][0] = convert3to1(convKeyArrb4[h], keyArr2d2Sblm, h, 0, h, ke - 1); //keyArr2d22 diambil dari data sebelumnya cr harus selalun ngikut round
        }

        //blok 2 sampai 4 perulangan 4 kali
        for (int i = 1; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                //System.out.println("i : " + i + ", j : " + j);
                keyArr2d24[j][i] = convert3to1O(keyArr2d2Sblm[j][i], keyArr2d24[j][i - 1]);
            }
        }

        /*printlnn("");
        printlnn("");
        System.out.println("key round " + ke + " : " + Arrays.deepToString(keyArr2d24));
        printlnn("");
        printlnn("");*/
        return keyArr2d24;

    }

    private String[][] makeRound(int ke, String[][] keyArr2d2Sblm) {

        //=========================================   4   ==========================================
        //System.out.println();

        String c4b14 = keyArr2d2Sblm[1][3];
        //============================
        String c4b24 = keyArr2d2Sblm[2][3];
        //============================
        String c4b34 = keyArr2d2Sblm[3][3];
        //============================
        String c4b44 = keyArr2d2Sblm[0][3];
        //============================

        //input data diatas dalam 1 var array
        String[] convKeyArrb4 = {c4b14, c4b24, c4b34, c4b44};

        //LINE FOR ROUND 4
        String[][] keyArr2d24 = new String[4][4]; //buat array baru untuk round 1

        //blok 1 perulangan 4 kali
        for (int h = 0; h < 4; h++) {
            keyArr2d24[h][0] = convert3to1(convKeyArrb4[h], keyArr2d2Sblm, h, 0, h, ke - 1); //keyArr2d22 diambil dari data sebelumnya cr harus selalun ngikut round
        }

        //blok 2 sampai 4 perulangan 4 kali
        for (int i = 1; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                //System.out.println("i : " + i + ", j : " + j);
                keyArr2d24[j][i] = convert3to1O(keyArr2d2Sblm[j][i], keyArr2d24[j][i - 1]);
            }
        }

        /*printlnn("");
        printlnn("");
        System.out.println("key round " + ke + " : " + Arrays.deepToString(keyArr2d24));
        printlnn("");
        printlnn("");*/
        return keyArr2d24;

    }

    private String changeIndex(String[] array) {//membalekkan dan mengubah binary jadi angka 76543210 sesuai posisi 0 atau 1 nya
        String ptrStr = "";
        int a = 7;
        for (int i = 0; i < array.length; i++) {
            if (Integer.parseInt(array[i]) != 0) {
                ptrStr += String.valueOf(a);
            }
            a--;
        }
        return ptrStr;
    }

    //untuk column kedua s/d 4 sama rumus
    private String convert3to1O(String c2b2, String keyarr2d2Ind) { //convert yg bukan 1, karna 1 itu beda jalannya
        String hBc1b4 = hexToBin(keyarr2d2Ind);
        //System.out.println(hBc1b4);
        String hBh4b4 = hexToBin(c2b2);
        //System.out.println(hBh4b4);
        //========================

        // PERUBAHAN 1.KEEMPAT (column 1)
        //System.out.println();
        //convert 3 binary menjadi sama panjangnya agar bisa di XOR
        //check length
        int panjangArr4 = check2Length(hBc1b4, hBh4b4);

        //convert binary jadi sama panjangnya
        String hBc1b4cv = convertArr(hBc1b4, panjangArr4);
        String hBh4b4cv = convertArr(hBh4b4, panjangArr4);

        //System.out.println(hBc1b4 + " ==> " + hBc1b4cv);
        //System.out.println(hBh4b4 + " ==> " + hBh4b4cv);

        //System.out.println("");
        //pentotalan XOR binary 1 dan 2
        String ttlperKed4 = arrToStr(totalXOR(hBc1b4cv, hBh4b4cv));
        //System.out.println("total perked4 : " + ttlperKed4);

        //binary to hex

        //System.out.println();
        //System.out.println("[" + b + "," + c + "] : " + hexTtl12d304);

        //System.out.println("");


        return binToHex(ttlperKed4);
    }

    //untuk column pertama yg berbeda rumus dgn column lain (b = baris, c = column; br = baris rcon, cr = column rcon)
    private String convert3to1(String c4b4, String[][] keyArr2d, int b, int c, int br, int cr) { // convert yg bagian baris pertama utk semua round dengan rumus column 1 baris 1 XOR subtype baris 1 column 4 XOR rcon

        String[] pch44 = c4b4.split("");
        String h4b4 = box[ConvertStringToInt(pch44[0])][ConvertStringToInt(pch44[1])];
        //System.out.println("h4b4 : " + h4b4); // Wi-1.4
        String c1b4 = keyArr2d[b][c]; // Wi-4.4
        String r1b4 = rcon[br][cr]; // Rcon1.4

        // Convert hex to binary FOR 14
        String hBc1b4 = hexToBin(c1b4);
        //System.out.println(hBc1b4);
        String hBh4b4 = hexToBin(h4b4);
        //System.out.println(hBh4b4);
        String hBr1c4 = hexToBin(r1b4);
        //System.out.println(hBr1c4);
        //========================


        // PERUBAHAN 1.KEEMPAT (column 1)
        //System.out.println();
        //convert 3 binary menjadi sama panjangnya agar bisa di XOR
        //check length
        int panjangArr4 = check3Length(hBc1b4, hBh4b4, hBr1c4);

        //convert binary jadi sama panjangnya
        String hBc1b4cv = convertArr(hBc1b4, panjangArr4);
        String hBh4b4cv = convertArr(hBh4b4, panjangArr4);
        String hBr1c4cv = convertArr(hBr1c4, panjangArr4);

        //System.out.println(hBc1b4 + " ==> " + hBc1b4cv);
        //System.out.println(hBh4b4 + " ==> " + hBh4b4cv);
        //System.out.println(hBr1c4 + " ==> " + hBr1c4cv);

        //System.out.println("");
        //pentotalan XOR binary 1 dan 2
        String ttlperKed4 = arrToStr(totalXOR(hBc1b4cv, hBh4b4cv));
        //System.out.println("total perked4 : " + ttlperKed4);

        //pentotalan XOR binary ttl12 dan 3
        String ttl12d34 = arrToStr(totalXOR(ttlperKed4, hBr1c4cv));
        //System.out.println("total ttl12d34 : " + ttl12d34);

        //binary to hex

        //System.out.println();
        //System.out.println("[" + b + "," + c + "] : " + hexTtl12d304);

        //System.out.println("");
        // ======================

        return binToHex(ttl12d34);
    }

    private String convertArr(String hBc1b1, int panjangArr) { //convert arr menghasilkan string dengan panjang digit yg sama dengan yg ingin di XOR
        String[] hbc1biArr = hBc1b1.split("");
        String[] conCust = new String[panjangArr];
        if (hBc1b1.length() != panjangArr) {
            int sisa = panjangArr - hBc1b1.length();
            for (int i = 0; i < hbc1biArr.length; i++) {
                conCust[i + sisa] = hbc1biArr[i];
            }
            for (int i = 0; i < sisa; i++) {
                conCust[i] = "0";
            }
            return arrToStr(Arrays.toString(conCust));
        } else {
            return hBc1b1;
        }
    }

    public String arrToStr(String text) { // replace array to string agar tampilan outputnya jadi canting tanpa kurang siku dan spasi koma
        return text.replace(", ", "").replace("[", "").replace("]", "");
    }

    public int check3Length(String pertama, String kedua, String ketiga) { //menentukan karakter mana yg paling panjang diantara 3 binary
        if (pertama.length() >= kedua.length()) {
            if (ketiga.length() >= pertama.length()) {
                return ketiga.length();
            } else {
                return pertama.length();
            }
        } else {
            if (ketiga.length() >= kedua.length()) {
                return ketiga.length();
            } else {
                return kedua.length();
            }
        }
    }

    public int check2Length(String pertama, String kedua) { //menentukan karakter mana yg paling panjang diantara 2 binary
        if (pertama.length() >= kedua.length()) {
            return pertama.length();
        } else {
            return kedua.length();
        }
    }

    public String totalXOR(String pertama, String kedua) { //menXOR kan 2 buat binary

        /*printlnn("============================");
        printlnn("pertama total xor : " + pertama);
        printlnn("kedua total xor : " + kedua);*/

        String[] perArr = pertama.split("");
        String[] kedArr = kedua.split("");
        String[] hasArr = new String[perArr.length];

        for (int i = 0; i < perArr.length; i++) {
            if (perArr[i] == null || kedArr[i] == null) {
                if (perArr[i] == null) {
                    hasArr[i] = kedArr[i];
                } else {
                    hasArr[i] = perArr[i];
                }
            } else {
                if (perArr[i].equals(kedArr[i])) {
                    hasArr[i] = "0";
                } else {
                    hasArr[i] = "1";
                }
            }
        }

        return Arrays.toString(hasArr);
    }

    static String hexToBin(String s) {
        return new BigInteger(s, 16).toString(2);
    }

    static String binToHex(String s) {
        return new BigInteger(s, 2).toString(16);
    }

    public int ConvertStringToInt(String hexBox) { //mengubah nilai yg lebih dari 9 menjadi huruf untuk box
        switch (hexBox) {
            case "a":
                return 10;
            case "b":
                return 11;
            case "c":
                return 12;
            case "d":
                return 13;
            case "e":
                return 14;
            case "f":
                return 15;
            default:
                return Integer.parseInt(hexBox);
        }
    }

    public String toHex(String arg) {
        return String.format("%x", new BigInteger(1, arg.getBytes()));
    }

}
