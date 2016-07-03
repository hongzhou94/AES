import java.io.*;

public class AES {
    private static boolean verbose = false;
    private static int keySize = 256;
    private static int expanded_keySize = 240;

    private final static int[] LogTable = {
            0, 0, 25, 1, 50, 2, 26, 198, 75, 199, 27, 104, 51, 238, 223, 3,
            100, 4, 224, 14, 52, 141, 129, 239, 76, 113, 8, 200, 248, 105, 28, 193,
            125, 194, 29, 181, 249, 185, 39, 106, 77, 228, 166, 114, 154, 201, 9, 120,
            101, 47, 138, 5, 33, 15, 225, 36, 18, 240, 130, 69, 53, 147, 218, 142,
            150, 143, 219, 189, 54, 208, 206, 148, 19, 92, 210, 241, 64, 70, 131, 56,
            102, 221, 253, 48, 191, 6, 139, 98, 179, 37, 226, 152, 34, 136, 145, 16,
            126, 110, 72, 195, 163, 182, 30, 66, 58, 107, 40, 84, 250, 133, 61, 186,
            43, 121, 10, 21, 155, 159, 94, 202, 78, 212, 172, 229, 243, 115, 167, 87,
            175, 88, 168, 80, 244, 234, 214, 116, 79, 174, 233, 213, 231, 230, 173, 232,
            44, 215, 117, 122, 235, 22, 11, 245, 89, 203, 95, 176, 156, 169, 81, 160,
            127, 12, 246, 111, 23, 196, 73, 236, 216, 67, 31, 45, 164, 118, 123, 183,
            204, 187, 62, 90, 251, 96, 177, 134, 59, 82, 161, 108, 170, 85, 41, 157,
            151, 178, 135, 144, 97, 190, 220, 252, 188, 149, 207, 205, 55, 63, 91, 209,
            83, 57, 132, 60, 65, 162, 109, 71, 20, 42, 158, 93, 86, 242, 211, 171,
            68, 17, 146, 217, 35, 32, 46, 137, 180, 124, 184, 38, 119, 153, 227, 165,
            103, 74, 237, 222, 197, 49, 254, 24, 13, 99, 140, 128, 192, 247, 112, 7};
    private final static int[] AlogTable = {
            1, 3, 5, 15, 17, 51, 85, 255, 26, 46, 114, 150, 161, 248, 19, 53,
            95, 225, 56, 72, 216, 115, 149, 164, 247, 2, 6, 10, 30, 34, 102, 170,
            229, 52, 92, 228, 55, 89, 235, 38, 106, 190, 217, 112, 144, 171, 230, 49,
            83, 245, 4, 12, 20, 60, 68, 204, 79, 209, 104, 184, 211, 110, 178, 205,
            76, 212, 103, 169, 224, 59, 77, 215, 98, 166, 241, 8, 24, 40, 120, 136,
            131, 158, 185, 208, 107, 189, 220, 127, 129, 152, 179, 206, 73, 219, 118, 154,
            181, 196, 87, 249, 16, 48, 80, 240, 11, 29, 39, 105, 187, 214, 97, 163,
            254, 25, 43, 125, 135, 146, 173, 236, 47, 113, 147, 174, 233, 32, 96, 160,
            251, 22, 58, 78, 210, 109, 183, 194, 93, 231, 50, 86, 250, 21, 63, 65,
            195, 94, 226, 61, 71, 201, 64, 192, 91, 237, 44, 116, 156, 191, 218, 117,
            159, 186, 213, 100, 172, 239, 42, 126, 130, 157, 188, 223, 122, 142, 137, 128,
            155, 182, 193, 88, 232, 35, 101, 175, 234, 37, 111, 177, 200, 67, 197, 84,
            252, 31, 33, 99, 165, 244, 7, 9, 27, 45, 119, 153, 176, 203, 70, 202,
            69, 207, 74, 222, 121, 139, 134, 145, 168, 227, 62, 66, 198, 81, 243, 14,
            18, 54, 90, 238, 41, 123, 141, 140, 143, 138, 133, 148, 167, 242, 13, 23,
            57, 75, 221, 124, 132, 151, 162, 253, 28, 36, 108, 180, 199, 82, 246, 1};
    private static int[] sbox = {
            0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
            0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
            0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
            0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
            0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
            0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
            0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
            0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
            0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
            0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
            0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
            0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
            0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
            0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
            0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
            0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16};

    private static int[] inv_s = {
            0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
            0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
            0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
            0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
            0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
            0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
            0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
            0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
            0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
            0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
            0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
            0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
            0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
            0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
            0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
            0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D};
    private static int[] rcon = {
            0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
            0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39,
            0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
            0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
            0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
            0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
            0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b,
            0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
            0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
            0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20,
            0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35,
            0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
            0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
            0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63,
            0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd,
            0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d};

    //Invoke with 'java AES e keyfile plaintext v 256' for 256 bit verbose encryption
    //Invoke with 'java AES d keyfile plaintext n 128' for 128 bit non-verbose decryption
    public static void main(String[] args) throws IOException {

        // Read in 256 bit key. Key file is args[1], plaintext file is args[2]
        int[] key_in = new int[keySize / 8]; // 1D key array

        if (args[3].equals("v")) verbose = true;

        keySize = Integer.parseInt(args[4]);
        if (keySize == 128) expanded_keySize = 176;
        else if (keySize == 192) expanded_keySize = 208;

        int[] expanded = new int[expanded_keySize]; // 1D expanded key

        try (BufferedReader br = new BufferedReader(new FileReader(args[1]))) {
            String line;
            while ((line = br.readLine()) != null) {
                for (int i = 0; i < keySize / 4; i += 2) {
                    String hexByte = "" + line.charAt(i) + line.charAt(i + 1);
                    key_in[i / 2] = (Integer.parseInt(hexByte, 16) & 0xff);
                }
            }
        }

        //File for output
        File fout;
        if (args[0].equals("e")) fout = new File(args[2] + ".enc");
        else fout = new File(args[2] + ".dec");

        FileOutputStream fos = new FileOutputStream(fout);
        BufferedWriter bw = new BufferedWriter(new OutputStreamWriter(fos));

        // Copy first keySize/8 bytes into expanded key
        for (int i = 0; i < keySize / 8; i++) {
            expanded[i] = key_in[i];
        }

        //expand key
        if (keySize == 256)
            keyExpand(expanded);
        else if (keySize == 128)
            keyExpand_128(expanded);
        else if (keySize == 192)
            keyExpand_192(expanded);

        int[] plaintext = new int[16];
        long timeResult = (long) 0.0;

        //read input file and encrypt, writing encrypted text to file line by line
        try (BufferedReader br1 = new BufferedReader(new FileReader(args[2]))) {
            String line;
            while ((line = br1.readLine()) != null) {
                for (int i = 0; i < 32; i += 2) {
                    String hexByteText = "" + line.charAt(i) + line.charAt(i + 1);
                    plaintext[i / 2] = (Integer.parseInt(hexByteText, 16) & 0xff);
                }

                if (verbose) {
                    System.out.println("The Plaintext is: ");
                    printText2d(plaintext);
                    System.out.println();

                    System.out.println("The CipherKey is: ");
                    for (int i = 0; i < 4; i++) {
                        for (int j = 0; j < keySize / 32; j++) {
                            if (((key_in[i + j * 4] >> 4) & 0xf) == 0) {
                                System.out.print(0);
                            }
                            System.out.print(Integer.toHexString(key_in[i + j * 4]).toUpperCase() + " ");
                        }
                        System.out.println();
                    }
                    System.out.println();

                    System.out.println("The expanded key is: ");
                    for (int y = 0; y < 4; y++) {
                        int count = 0;
                        for (int z = 0; z < expanded_keySize / 4; z++) {
                            if (((expanded[y + z * 4] >> 4) & 0xf) == 0) {
                                System.out.print(0);
                            }
                            System.out.print(Integer.toHexString(expanded[(y) + z * 4]).toUpperCase());
                            if (count == 3) {
                                System.out.print(" ");
                                count = 0;
                            } else count++;
                        }
                        System.out.println();
                    }
                    System.out.println();
                }

                if (args[0].equals("e")) {
                    long start = System.nanoTime();
                    encrypt(plaintext, expanded);
                    long end = System.nanoTime();
                    timeResult += end - start;

                    System.out.println("The ciphertext:");
                    printText2d(plaintext);
                    System.out.println();
                } else {
                    long start = System.nanoTime();
                    decrypt(plaintext, expanded);
                    long end = System.nanoTime();
                    timeResult += end - start;

                    System.out.println("The decryption of the ciphertext:");
                    printText2d(plaintext);

                    if (verbose) {
                        System.out.println("\nThe decryption of the ciphertext:");
                        printArray(plaintext);
                    }
                    System.out.println();
                }
                for (int i = 0; i < 16; i++) {
                    if (((plaintext[i] >> 4) & 0xf) == 0) {
                        bw.write("0");
                    }
                    bw.write(Integer.toHexString(plaintext[i]).toUpperCase());
                }
                bw.write("\n");
            }
        }

        if (verbose) {
            System.out.println(args[0].equals("e") ? ("Encryption took: " + (timeResult / 1000000000.0) +
                    "sec") : ("Decryption took: " + (timeResult / 1000000000.0) + "sec"));
        }

        bw.close();
    }

    public static void keyExpand(int[] in) {
        int c = 32;
        int t[] = new int[4];
        int i = 1;

        while (c < 240) {
            for (int j = 0; j < 4; j++) {
                t[j] = in[j + c - 4];
            }
            if (c % 32 == 0) {
                t = schedule_core(t, i);
                i++;
            }
            if (c % 32 == 16) {
                for (int a = 0; a < 4; a++) {
                    t[a] = sbox_lookup(t[a]);
                }
            }
            for (int a = 0; a < 4; a++) {
                in[c] = (in[c - 32] ^ t[a]);
                c++;
            }
        }
    }

    public static void keyExpand_128(int[] in) {
        int c = 16;
        int t[] = new int[4];
        int i = 1;

        while (c < 176) {
            for (int j = 0; j < 4; j++) {
                t[j] = in[j + c - 4];
            }

            if (c % 16 == 0) {
                t = schedule_core(t, i);
                i++;
            }

            for (int a = 0; a < 4; a++) {
                in[c] = in[c - 16] ^ t[a];
                c++;
            }
        }
    }

    public static void keyExpand_192(int[] in) {
        int c = 24;
        int t[] = new int[4];
        int i = 1;

        while (c < 208) {
            for (int j = 0; j < 4; j++) {
                t[j] = in[j + c - 4];
            }
            if (c % 24 == 0) {
                t = schedule_core(t, i);
                i++;
            }
            for (int a = 0; a < 4; a++) {
                in[c] = (in[c - 24] ^ t[a]);
                c++;
            }
        }
    }

    private static int[] schedule_core(int[] in, int j) {
        int out[] = new int[4];

        for (int i = 0; i < 4; i++) {
            out[i] = in[i];
        }
        int temp = out[0];
        out[0] = out[1];
        out[1] = out[2];
        out[2] = out[3];
        out[3] = temp;

        for (int i = 0; i < 4; i++) {
            out[i] = sbox_lookup(out[i]);
        }

        //rcon lookup table is used because calculating it on the fly didn't work
        out[0] ^= rcon[j];
        return out;
    }

    private static int sbox_lookup(int in) {
        int msb, lsb;
        lsb = in & 0xf;
        msb = (in >> 4) & 0xf;
        return sbox[(msb * 16) + lsb];
    }

    private static int inv_sbox_lookup(int in) {
        int msb, lsb;
        lsb = in & 0xf;
        msb = (in >> 4) & 0xf;
        return inv_s[(msb * 16) + lsb];
    }

    private static int[] makeRoundKey(int round, int[] expanded) {
        int[] result = new int[16];
        for (int i = 0; i < 16; i++) {
            result[i] = expanded[(round * 16) + i];
        }

        return result;
    }

    private static void encrypt(int[] plaintext, int[] expanded) {
        addRoundKey(plaintext, expanded, 0);

        if (verbose) {
            System.out.println("After addRoundKey(0):");
            printArray(plaintext);
        }

        int rounds = 14;
        if(keySize == 128) rounds = 10;
        if(keySize == 192) rounds = 12;

        for (int i = 1; i <= rounds; i++) {
            subBytes(plaintext);
            shiftRows(plaintext);
            if (i != rounds) {
                int[][] temp = new int[4][4];
                for (int j = 0; j < 4; j++) {
                    for (int k = 0; k < 4; k++) {
                        temp[j][k] = plaintext[j + k * 4];
                    }
                }
                for (int j = 0; j < 4; j++) {
                    mixColumn2(j, temp);
                }
                for (int j = 0; j < 4; j++) {
                    for (int k = 0; k < 4; k++) {
                        plaintext[j + k * 4] = temp[j][k];
                    }
                }

                if (verbose) {
                    System.out.println("After mixColumns:");
                    printArray(plaintext);
                }
            }
            addRoundKey(plaintext, expanded, i);
            if (verbose) {
                System.out.println("After addRoundKey(" + i + "):");
                printArray(plaintext);
            }
        }
    }

    private static void decrypt(int[] plaintext, int[] expanded) {
        int rounds = 14;
        if(keySize == 128) rounds = 10;
        if(keySize == 192) rounds = 12;

        for (int i = rounds; i > 0; i--) {
            addRoundKey(plaintext, expanded, i);
            if (verbose) {
                System.out.println("After addRoundKey(" + i + "):");
                printArray(plaintext);
            }
            if (i != rounds) {
                int[][] temp = new int[4][4];
                for (int j = 0; j < 4; j++) {
                    for (int k = 0; k < 4; k++) {
                        temp[j][k] = plaintext[j + k * 4];
                    }
                }
                for (int j = 0; j < 4; j++) {
                    invMixColumn2(j, temp);
                }
                for (int j = 0; j < 4; j++) {
                    for (int k = 0; k < 4; k++) {
                        plaintext[j + k * 4] = temp[j][k];
                    }
                }
                if (verbose) {
                    System.out.println("After invMixColumns:");
                    printArray(plaintext);
                }
            }
            invShiftRows(plaintext);
            invSubBytes(plaintext);
        }
        addRoundKey(plaintext, expanded, 0);
        if (verbose) {
            System.out.println("After addRoundKey(0):");
            printArray(plaintext);
        }

    }

    private static void printArray(int[] plaintext) {
        for (int i = 0; i < 16; i++) {
            if (((plaintext[i] >> 4) & 0xf) == 0) {
                System.out.print(0);
            }
            System.out.print(Integer.toHexString(plaintext[i]).toUpperCase());
        }
        System.out.println();
    }

    private static void printText2d(int[] plaintext) {
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                if (((plaintext[i + j * 4] >> 4) & 0xf) == 0) {
                    System.out.print(0);
                }
                System.out.print(Integer.toHexString(plaintext[i + j * 4]).toUpperCase() + " ");
            }
            System.out.print("\n");
        }
    }

    private static void addRoundKey(int[] plaintext, int[] expanded, int round) {
        int[] roundKey = makeRoundKey(round, expanded);
        for (int i = 0; i < 16; i++) {
            plaintext[i] ^= roundKey[i];
        }
    }

    private static void subBytes(int[] plaintext) {
        for (int i = 0; i < 16; i++) {
            plaintext[i] = sbox_lookup(plaintext[i]);
        }
        if (verbose) {
            System.out.println("After subBytes:");
            printArray(plaintext);
        }
    }

    private static void invSubBytes(int[] plaintext) {
        for (int i = 0; i < 16; i++) {
            plaintext[i] = inv_sbox_lookup(plaintext[i]);
        }
        if (verbose) {
            System.out.println("After invSubBytes:");
            printArray(plaintext);
        }
    }

    ////////////////////////  the mixColumns Transformation ////////////////////////

    private static void shiftRows(int[] plaintext) {
        int temp[] = new int[16];
        for (int i = 0; i < 16; i++) {
            temp[i] = plaintext[i];
        }
        plaintext[0] = temp[0];

        int c = 1;
        for (int j = 5; j >= 1; j--) {
            for (int k = 0; k < 3; k++) {
                plaintext[c] = temp[j + k * 5];
                c++;
            }
        }

        if (verbose) {
            System.out.println("After shiftRows:");
            printArray(plaintext);
        }
    }

    private static void invShiftRows(int[] plaintext) {
        int temp[] = new int[16];
        for (int i = 0; i < 16; i++) {
            temp[i] = plaintext[i];
        }
        plaintext[0] = temp[0];

        int c = 1;
        for (int j = 13; j < 16; j++) {
            for (int k = 0; k < 5; k++) {
                plaintext[c] = temp[j - k * 3];
                c++;
            }
        }

        if (verbose) {
            System.out.println("After invShiftRows:");
            printArray(plaintext);
        }
    }

    private static int mul(int a, int b) {
        int inda = (a < 0) ? (a + 256) : a;
        int indb = (b < 0) ? (b + 256) : b;

        if ((a != 0) && (b != 0)) {
            int index = (LogTable[inda] + LogTable[indb]);
            return (AlogTable[index % 255]);
        } else
            return 0;
    } // mul

    // In the following two methods, the input c is the column number in
    // your evolving state matrix st (which originally contained
    // the plaintext input but is being modified).  Notice that the state here is defined as an
    // array of bytes.  If your state is an array of integers, you'll have
    // to make adjustments.

    private static void mixColumn2(int c, int[][] st) {
        // This is another alternate version of mixColumn, using the
        // logtables to do the computation.

        int a[] = new int[4];

        // note that a is just a copy of st[.][c]
        for (int i = 0; i < 4; i++)
            a[i] = st[i][c];

        // This is exactly the same as mixColumns1, if
        // the mul columns somehow match the b columns there.
        st[0][c] = (mul(2, a[0]) ^ a[2] ^ a[3] ^ mul(3, a[1]));
        st[1][c] = (mul(2, a[1]) ^ a[3] ^ a[0] ^ mul(3, a[2]));
        st[2][c] = (mul(2, a[2]) ^ a[0] ^ a[1] ^ mul(3, a[3]));
        st[3][c] = (mul(2, a[3]) ^ a[1] ^ a[2] ^ mul(3, a[0]));
    } // mixColumn2

    private static void invMixColumn2(int c, int[][] st) {
        int a[] = new int[4];

        // note that a is just a copy of st[.][c]
        for (int i = 0; i < 4; i++)
            a[i] = st[i][c];

        st[0][c] = (mul(0xE, a[0]) ^ mul(0xB, a[1]) ^ mul(0xD, a[2]) ^ mul(0x9, a[3]));
        st[1][c] = (mul(0xE, a[1]) ^ mul(0xB, a[2]) ^ mul(0xD, a[3]) ^ mul(0x9, a[0]));
        st[2][c] = (mul(0xE, a[2]) ^ mul(0xB, a[3]) ^ mul(0xD, a[0]) ^ mul(0x9, a[1]));
        st[3][c] = (mul(0xE, a[3]) ^ mul(0xB, a[0]) ^ mul(0xD, a[1]) ^ mul(0x9, a[2]));
    } // invMixColumn2


}
