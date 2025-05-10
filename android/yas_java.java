// test763 : YAS java crypto module2

import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;

import java.util.Arrays;
import java.io.*;
import java.util.concurrent.*;

import java.nio.file.*;
import java.nio.charset.StandardCharsets;

// support functions
class Support {
    int count;
    ExecutorService ex;

    // fill data with random
    void randfill(byte[] data) {
        SecureRandom s = new SecureRandom();
        s.nextBytes(data);
    }

    // join bytes
    byte[] append(byte[] a, byte[] b) {
        byte[] res = new byte[a.length + b.length];
        System.arraycopy(a, 0, res, 0, a.length);
        System.arraycopy(b, 0, res, a.length, b.length);
        return res;
    }

    // padding & unpadding
    byte[] pad(byte[] data, boolean ispad) {
        if (ispad) {
            int padlen = 16 - data.length % 16;
            byte[] res = new byte[data.length + padlen];
            System.arraycopy(data, 0, res, 0, data.length);
            for (int i = data.length; i < res.length; i++) { res[i] = (byte) padlen; }
            return res;
        } else {
            int padlen = data[data.length - 1] & 0xFF;
            return Arrays.copyOfRange(data, 0, data.length - padlen);
        }
    }

    // get file size
    long getsize(String file) {
        File temp = new File(file);
        return temp.length();
    }

    // zip files -> ./temp
    void dozip(String[] files) throws Exception {
        FileOutputStream f = new FileOutputStream("./temp");
        f.write(new byte[] { (byte) (files.length % 256), (byte) (files.length / 256) });
        byte[] buffer;

        for (int i = 0; i < files.length; i++) {
            String name = files[i].replaceAll("\\\\", "/"); // actual file name
            name = name.substring(name.lastIndexOf("/") + 1);
            buffer = name.getBytes(StandardCharsets.UTF_8);
            f.write(new byte[] { (byte) (buffer.length % 256), (byte) (buffer.length / 256) });
            f.write(buffer);

            long fsize = getsize(files[i]); // file size
            buffer = new byte[8];
            for (int j = 0; j < 8; j++) {
                buffer[j] = (byte) (fsize % 256);
                fsize /= 256;
            }
            f.write(buffer);

            fsize = getsize(files[i]); // buffered file copy
            long num0 = fsize / 1048576;
            long num1 = fsize % 1048576;
            FileInputStream t = new FileInputStream(files[i]);
            buffer = new byte[1048576];
            for (long j = 0; j < num0; j++) {
                t.read(buffer);
                f.write(buffer);
            }
            buffer = new byte[(int) num1];
            t.read(buffer);
            f.write(buffer);
            t.close();
        }
        f.close();
    }

    // unzip files : ./temp -> path + files
    void unzip(String unpackDir) throws Exception {
        unpackDir = unpackDir.replaceAll("\\\\", "/"); // set unpack directory
        if (unpackDir.equals("")) {
            unpackDir = "./";
        } else {
            if (!unpackDir.substring(unpackDir.length() - 1).equals("/")) {
                unpackDir = unpackDir + "/";
            }
        }

        FileInputStream f = new FileInputStream("./temp");
        byte[] buffer = new byte[2];
        f.read(buffer);
        int num = (buffer[0] & 0xFF) + (buffer[1] & 0xFF) * 256; // number of files

        for (int i = 0; i < num; i++) {
            buffer = new byte[2];
            f.read(buffer);
            buffer = new byte[(buffer[0] & 0xFF) + (buffer[1] & 0xFF) * 256];
            f.read(buffer);
            String name = new String(buffer, StandardCharsets.UTF_8); // file name

            long fsize = 0; // file size
            buffer = new byte[8];
            f.read(buffer);
            for (int j = 7; j >= 0; j--) { fsize = fsize * 256 + (buffer[j] & 0xFF); }

            long num0 = fsize / 1048576; // buffered file copy
            long num1 = fsize % 1048576;
            FileOutputStream t = new FileOutputStream(unpackDir + name);
            buffer = new byte[1048576];
            for (long j = 0; j < num0; j++) {
                f.read(buffer);
                t.write(buffer);
            }
            buffer = new byte[(int) num1];
            f.read(buffer);
            t.write(buffer);
            t.close();
        }
        f.close();
    }

    // key expand inline
    byte[] expkey(byte[] pre, byte[] sub) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA3-256");
        byte[] res = sub;
        for (int i = 0; i < 10000; i++) { res = digest.digest(append(pre, res)); }
        return res;
    }

    // key expand (get key/iv)
    byte[][] getkey(byte[] ckey) throws Exception {
        byte[][] order = new byte[16][];
        byte[][] res = new byte[32][];
        ex = Executors.newFixedThreadPool(16);

        for (int i = 0; i < 16; i++) {
            int temp = (7 * i) % 16; // round st point
            byte[] pre;
            byte[] sub;
            if (temp > 8) {
                pre = Arrays.copyOfRange(ckey, 8 * temp - 64, 8 * temp);
                sub = append(Arrays.copyOfRange(ckey, 8 * temp, ckey.length), Arrays.copyOfRange(ckey, 0, 8 * temp - 64));
            } else {
                pre = append(Arrays.copyOfRange(ckey, 8 * temp + 64, ckey.length), Arrays.copyOfRange(ckey, 0, 8 * temp));
                sub = Arrays.copyOfRange(ckey, 8 * temp, 8 * temp + 64);
            }
            order[i] = ex.submit(() -> expkey(pre, sub)).get();
        }
        ex.shutdown();

        for (int i = 0; i < 16; i++) {
            res[i] = Arrays.copyOfRange(order[i], 0, 16);
            res[i + 16] = Arrays.copyOfRange(order[i], 16, 32);
        }
        return res;
    }

    // AES128 enc & dec, no padding
    byte[] aes128(byte[] key, byte[] iv, byte[] data, boolean isenc) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        if (isenc) {
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
        } else {
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
        }
        return cipher.doFinal(data);
    }

    // encrypt ./temp -> path, 8 threads
    void encrypt(String msg, String pw, String path) throws Exception {
        byte[] salt = new byte[32]; // generate random key
        randfill(salt);
        byte[] ckey = new byte[128];
        randfill(salt);
        byte[] iv = new byte[16];
        randfill(salt);

        MessageDigest digest = MessageDigest.getInstance("SHA3-256"); // get pwhash & master key
        byte[] pwhash = pw.getBytes(StandardCharsets.UTF_8);
        for (int i = 0; i < 100000; i++) { pwhash = digest.digest(append(salt, pwhash)); }
        byte[] mkey = pw.getBytes(StandardCharsets.UTF_8);
        for (int i = 0; i < 10000; i++) { mkey = digest.digest(append(mkey, salt)); }

        byte[] msgdata = msg.getBytes(StandardCharsets.UTF_8); // make header
        byte[] ckeydata = aes128(Arrays.copyOfRange(mkey, 16, 32), Arrays.copyOfRange(mkey, 0, 16), ckey, true);
        byte[] header = "OTE1".getBytes(StandardCharsets.UTF_8);
        header = append(append(header, new byte[] { (byte) (msgdata.length % 256), (byte) (msgdata.length / 256) }), msgdata);
        header = append(append(append(append(header, salt), pwhash), ckeydata), iv);

        byte[][] keys = getkey(ckey); // get threads key
        byte[][] ivs = new byte[32][];
        Arrays.fill(ivs, iv);
        long fsize = getsize("./temp"); // get file size
        long num0 = fsize / 131072; // chunk num
        long num1 = fsize % 131072; // left size

        byte[][] order = new byte[8][];
        byte[][] write = new byte[32][];
        Arrays.fill(order, null);
        Arrays.fill(write, null);
        ex = Executors.newFixedThreadPool(8);
        count = 0;
        FileOutputStream f = new FileOutputStream(path);
        FileInputStream t = new FileInputStream("./temp");
        f.write(header);

        for (long i = 0; i < num0; i++) {
            byte[] buffer = new byte[131072]; // read & compute
            t.read(buffer);
            count = (int) (i % 32); // keyiv position
            order[(int) (i % 8)] = ex.submit(() -> aes128(keys[count], ivs[count], buffer, true)).get();

            if (i % 8 == 7) { // move data from order to write
                ex.shutdown();
                ex = Executors.newFixedThreadPool(8);
                for (int j = 0; j < 8; j++) { write[count - 7 + j] = order[j]; }
            }

            if (i % 32 == 31) { // write data
                for (int j = 0; j < 32; j++) {
                    ivs[j] = Arrays.copyOfRange(write[j], 131056, 131072);
                    f.write(write[j]);
                }
                Arrays.fill(order, null);
                Arrays.fill(write, null);
            }
        }

        if (num0 % 8 != 0) {
            ex.shutdown();
            for (int i = 0; i < num0 % 8; i++) { write[count - (int) (num0 % 8) + i + 1] = order[i]; }
        }
        if (num0 % 32 != 0) {
            for (int i = 0; i < num0 % 32; i++) { f.write(write[i]); }
        }
        byte[] buffer = new byte[(int) num1];
        t.read(buffer);
        buffer = aes128(keys[(int) (num0 % 32)], ivs[(int) (num0 % 32)], pad(buffer, true), true);
        f.write(buffer);
        t.close();
        f.close();
    }

    // decrypt path -> ./temp, 8 threads
    void decrypt(String pw, String path) throws Exception {
        FileInputStream f = new FileInputStream(path);
        byte[] buf = new byte[6];
        f.read(buf);
        int msglen = (buf[4] & 0xFF) + (buf[5] & 0xFF) * 256;
        buf = new byte[msglen];
        f.read(buf);
        byte[] salt = new byte[32];
        f.read(salt);
        byte[] pwhash = new byte[32];
        f.read(pwhash);
        byte[] ckeydata = new byte[128];
        f.read(ckeydata);
        byte[] iv = new byte[16];
        f.read(iv);

        MessageDigest digest = MessageDigest.getInstance("SHA3-256"); // get nph & master key
        byte[] nph = pw.getBytes(StandardCharsets.UTF_8);
        for (int i = 0; i < 100000; i++) { nph = digest.digest(append(salt, nph)); }
        byte[] mkey = pw.getBytes(StandardCharsets.UTF_8);
        for (int i = 0; i < 10000; i++) { mkey = digest.digest(append(mkey, salt)); }
        if (!Arrays.equals(pwhash, nph)) { // check password
            f.close();
            throw new Exception("InvalidPassword");
        }

        byte[] ckey = aes128(Arrays.copyOfRange(mkey, 16, 32), Arrays.copyOfRange(mkey, 0, 16), ckeydata, false);
        byte[][] keys = getkey(ckey); // get threads key
        byte[][] ivs = new byte[32][];
        Arrays.fill(ivs, iv);
        long fsize = getsize(path) - 214 - msglen; // get actual file size
        long num0 = fsize / 131072; // chunk num
        long num1 = fsize % 131072; // left size
        if (num1 == 0) {
            num0--;
            num1 = 131072;
        }

        FileOutputStream t = new FileOutputStream("./temp");
        byte[][] order = new byte[8][];
        byte[][] write = new byte[32][];
        ex = Executors.newFixedThreadPool(8);
        Arrays.fill(order, null);
        Arrays.fill(write, null);

        for (long i = 0; i < num0; i++) {
            byte[] buffer = new byte[131072]; // read & compute
            f.read(buffer);
            count = (int) (i % 32); // keyiv position
            order[(int) (i % 8)] = ex.submit(() -> aes128(keys[count], ivs[count], buffer, false)).get();
            ivs[count] = Arrays.copyOfRange(buffer, 131056, 131072);

            if (i % 8 == 7) { // move data from order to write
                ex.shutdown();
                ex = Executors.newFixedThreadPool(8);
                for (int j = 0; j < 8; j++) { write[count - 7 + j] = order[j]; }
            }

            if (i % 32 == 31) { // write data
                for (int j = 0; j < 32; j++) { t.write(write[j]); }
                Arrays.fill(order, null);
                Arrays.fill(write, null);
            }
        }

        if (num0 % 8 != 0) {
            ex.shutdown();
            for (int i = 0; i < num0 % 8; i++) { write[count - (int) (num0 % 8) + i + 1] = order[i]; }
        }
        if (num0 % 32 != 0) {
            for (int i = 0; i < num0 % 32; i++) { t.write(write[i]); }
        }
        byte[] buffer = new byte[(int) num1];
        f.read(buffer);
        buffer = pad(aes128(keys[(int) (num0 % 32)], ivs[(int) (num0 % 32)], buffer, false), false);
        t.write(buffer);
        t.close();
        f.close();
    }

    // check file validity, read msg
    String view(String file) throws Exception {
        FileInputStream f = new FileInputStream(file);
        byte[] buffer = new byte[4];
        f.read(buffer);
        if (!Arrays.equals(buffer, "OTE1".getBytes(StandardCharsets.UTF_8))) {
            f.close();
            throw new Exception("InvalidFile");
        }

        buffer = new byte[2];
        f.read(buffer);
        int msglen = (buffer[0] & 0xFF) + (buffer[1] & 0xFF) * 256;
        buffer = new byte[msglen];
        f.read(buffer);
        f.close();
        return new String(buffer, StandardCharsets.UTF_8);
    }
}

// yas_java.java
public class yas_java {
    Support sup = new Support();
    public String msg = "YAS java crypto module2"; // user message
    public String err = ""; // error message

    public void Encrypt(String[] files, String pw, String path) {
        this.err = "";
        try {
            sup.dozip(files);
            sup.encrypt(msg, pw, path);
            Files.deleteIfExists(Paths.get("./temp"));
        } catch (Exception e) {
            this.err = e.getMessage();
        }
    }

    public void Decrypt(String pw, String path, String unpackDir) {
        this.err = "";
        try {
            sup.decrypt(pw, path);
            sup.unzip(unpackDir);
            Files.deleteIfExists(Paths.get("./temp"));
        } catch (Exception e) {
            this.err = e.getMessage();
        }
    }

    public void View(String file) {
        this.err = "";
        try {
            this.msg = sup.view(file);
        } catch (Exception e) {
            this.err = e.getMessage();
        }
    }
}
