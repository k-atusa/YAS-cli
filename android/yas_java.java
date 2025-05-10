// test673 : YAS java crypto module

import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;

import java.util.Arrays;
import java.io.*;
import java.util.concurrent.*;

import java.nio.file.*;
import java.nio.charset.StandardCharsets;

class bytearray {
  byte[] data;

  public bytearray() {
  }

  public bytearray(int bytelen) { // fill data with 0
    this.data = new byte[bytelen];
    Arrays.fill(this.data, (byte) 0);
  }

  public bytearray(String strin) { // string to utf-8 bytearray
    this.data = strin.getBytes(StandardCharsets.UTF_8);
  }

  void fromString(String strin) { // set data with string
    this.data = strin.getBytes(StandardCharsets.UTF_8);
  }

  void initByte(int bytelen) { // fill data with 0
    this.data = new byte[bytelen];
    Arrays.fill(this.data, (byte) 0);
  }

  void randByte(int bytelen) { // fill data with random byte
    SecureRandom s = new SecureRandom();
    this.data = new byte[bytelen];
    s.nextBytes(this.data);
  }

  void addByteFront(byte[] bytein) { // append at front
    byte[] temp = new byte[this.data.length + bytein.length];
    System.arraycopy(bytein, 0, temp, 0, bytein.length);
    System.arraycopy(this.data, 0, temp, bytein.length, this.data.length);
    this.data = temp;
  }

  void addByteBack(byte[] bytein) { // append at back
    byte[] temp = new byte[this.data.length + bytein.length];
    System.arraycopy(this.data, 0, temp, 0, this.data.length);
    System.arraycopy(bytein, 0, temp, this.data.length, bytein.length);
    this.data = temp;
  }

  String readData() { // print bytearray in hex
    String temp = "";
    for (int i = 0; i < this.data.length; i++) {
      temp = temp + String.format("%02X ", data[i]);
    }
    return temp;
  }
}

class engine {
  // padding, unpadding
  byte[] padding(byte[] data) {
    int paddingLength = 16 - (data.length % 16);
    byte paddingByte = (byte) paddingLength;

    byte[] paddedData = new byte[data.length + paddingLength];
    System.arraycopy(data, 0, paddedData, 0, data.length);
    for (int i = data.length; i < paddedData.length; i++) {
      paddedData[i] = paddingByte;
    }

    return paddedData;
  }

  byte[] unpadding(byte[] paddedData) {
    int paddingLength = paddedData[paddedData.length - 1] & 0xFF;
    byte[] unpaddedData = new byte[paddedData.length - paddingLength];
    System.arraycopy(paddedData, 0, unpaddedData, 0, unpaddedData.length);

    return unpaddedData;
  }

  // files -> tempkaesl
  void dozip(String[] targets) throws Exception {
    int num = targets.length;
    FileOutputStream f = new FileOutputStream("./tempkaesl");
    f.write(new byte[] { (byte) (num % 256), (byte) (num / 256) });

    for (int i = 0; i < num; i++) {
      String fname = targets[i];
      String tempname = fname.replaceAll("\\\\", "/");
      tempname = tempname.substring(tempname.lastIndexOf("/") + 1); // file name
      bytearray namebyte = new bytearray(tempname);
      int tempnum = namebyte.data.length; // file name size
      f.write(new byte[] { (byte) (tempnum % 256), (byte) (tempnum / 256) });
      f.write(namebyte.data);

      File file = new File(fname);
      long fsize = file.length(); // file size
      long tempsize = fsize;
      byte[] tempbyte = new byte[8];
      for (int j = 0; j < 8; j++) {
        tempbyte[j] = (byte) (tempsize % 256);
        tempsize = tempsize / 256;
      }
      f.write(tempbyte);

      long num0 = fsize / 1048576;
      long num1 = fsize % 1048576;
      FileInputStream t = new FileInputStream(fname);
      byte[] buffer = new byte[1048576];
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

  // tempkaesl -> path + files
  void unzip(String path) throws Exception { // path : folder path
    path = path.replaceAll("\\\\", "/");
    if (path.equals("")) {
      path = "./";
    } else {
      if (path.substring(path.length() - 1) != "/") {
        path = path + "/";
      }
    }

    FileInputStream f = new FileInputStream("tempkaesl");
    byte[] buffer = new byte[2];
    f.read(buffer);
    int num = (buffer[0] & 0xFF) + (buffer[1] & 0xFF) * 256;

    for (int i = 0; i < num; i++) {
      buffer = new byte[2];
      f.read(buffer);
      int namelen = (buffer[0] & 0xFF) + (buffer[1] & 0xFF) * 256;
      buffer = new byte[namelen];
      f.read(buffer);
      String namestr = new String(buffer, StandardCharsets.UTF_8);

      long filesize = 0;
      long multi = 1;
      buffer = new byte[8];
      f.read(buffer);
      for (int j = 0; j < 8; j++) {
        filesize = filesize + ((buffer[j] & 0xFF) * multi);
        if (j != 7) {
          multi = multi * 256;
        }
      }

      long num0 = filesize / 1048576;
      long num1 = filesize % 1048576;
      FileOutputStream t = new FileOutputStream(path + namestr);
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
  bytearray inline0(bytearray pre, bytearray sub) throws Exception {
    MessageDigest digest = MessageDigest.getInstance("SHA3-256");
    for (int i = 0; i < 10000; i++) {
      sub.addByteFront(pre.data);
      sub.data = digest.digest(sub.data);
    }
    return sub;
  }

  // key expand function
  bytearray[] expandkey(bytearray ckey) throws Exception { // ckey : bytearray
    bytearray[] order = new bytearray[16];
    bytearray[] out = new bytearray[32];
    ExecutorService ex = Executors.newFixedThreadPool(16);

    for (int i = 0; i < 16; i++) {
      bytearray pre = new bytearray();
      bytearray sub = new bytearray();
      int temp = (7 * i) % 16; // round st point
      if (temp > 8) {
        pre.data = Arrays.copyOfRange(ckey.data, 8 * temp - 64, 8 * temp);
        sub.data = Arrays.copyOfRange(ckey.data, 8 * temp, ckey.data.length);
        sub.addByteBack(Arrays.copyOfRange(ckey.data, 0, 8 * temp - 64));
      } else {
        pre.data = Arrays.copyOfRange(ckey.data, 8 * temp + 64, ckey.data.length);
        pre.addByteBack(Arrays.copyOfRange(ckey.data, 0, 8 * temp));
        sub.data = Arrays.copyOfRange(ckey.data, 8 * temp, 8 * temp + 64);
      }
      order[i] = ex.submit(() -> inline0(pre, sub)).get();
    }
    ex.shutdown();

    for (int i = 0; i < 16; i++) {
      bytearray temp = order[i];
      bytearray hash0 = new bytearray();
      bytearray hash1 = new bytearray();
      hash0.data = Arrays.copyOfRange(temp.data, 0, 16);
      hash1.data = Arrays.copyOfRange(temp.data, 16, 32);
      out[i] = hash0;
      out[i + 16] = hash1;
    }
    return out;
  }

  // short encryption no padding, 16B * n
  bytearray inline1(bytearray key, bytearray iv, bytearray indata) throws Exception {
    Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
    SecretKeySpec secretKey = new SecretKeySpec(key.data, "AES");
    IvParameterSpec ivSpec = new IvParameterSpec(iv.data);
    cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
    bytearray out = new bytearray();
    out.data = cipher.doFinal(indata.data);
    return out;
  }

  // enc, dec common class var
  int count;
  ExecutorService ex = Executors.newFixedThreadPool(1);

  // encrypt(tempkaesl) -> move to path, n process
  void encryptn(String msg, String pw, String path, int core) throws Exception {
    bytearray salt = new bytearray();
    salt.randByte(32); // salt bytearray

    bytearray ckey = new bytearray();
    ckey.randByte(128); // content key bytearray

    bytearray iv = new bytearray();
    iv.randByte(16); // iv bytearray

    MessageDigest digest = MessageDigest.getInstance("SHA3-256");
    bytearray pwhash = new bytearray(pw); // pwh bytearray
    for (int i = 0; i < 100000; i++) {
      pwhash.addByteFront(salt.data);
      pwhash.data = digest.digest(pwhash.data);
    }
    bytearray mkey = new bytearray(pw); // master key bytearray
    for (int i = 0; i < 10000; i++) {
      mkey.addByteBack(salt.data);
      mkey.data = digest.digest(mkey.data);
    }

    bytearray hintbyte = new bytearray(msg); // msg bytearray
    int hintsize = hintbyte.data.length;

    bytearray enckey = new bytearray();
    bytearray enciv = new bytearray();
    enckey.data = Arrays.copyOfRange(mkey.data, 16, 32);
    enciv.data = Arrays.copyOfRange(mkey.data, 0, 16);
    bytearray ckeydata = inline1(enckey, enciv, ckey);

    bytearray header = new bytearray("OTE1"); // header bytearray
    header.addByteBack(new byte[] { (byte) (hintsize % 256), (byte) (hintsize / 256) });
    header.addByteBack(hintbyte.data);
    header.addByteBack(salt.data);
    header.addByteBack(pwhash.data);
    header.addByteBack(ckeydata.data);
    header.addByteBack(iv.data);

    bytearray[] keys = expandkey(ckey); // 16B * 32 keys bytearray[]
    bytearray[] ivs = new bytearray[32];
    Arrays.fill(ivs, iv); // 16B * 32 ivs bytearray[]
    File file = new File("tempkaesl");
    long filesize = file.length(); // target size
    long chunknum0 = filesize / 131072; // chunk num
    long chunknum1 = filesize % 131072; // left size

    FileOutputStream f = new FileOutputStream(path);
    FileInputStream t = new FileInputStream("tempkaesl");

    f.write(header.data);
    bytearray[] order = new bytearray[core];
    bytearray[] write = new bytearray[32];
    ex = Executors.newFixedThreadPool(core);
    count = 0; // iv, key position
    bytearray voidarray = new bytearray(0);
    Arrays.fill(order, voidarray);
    Arrays.fill(write, voidarray);

    byte[] buffer = new byte[131072];
    byte[] tempwrite = new byte[4194304];
    for (long i = 0; i < chunknum0; i++) {
      t.read(buffer); // 128kb
      bytearray tempdata = new bytearray();
      tempdata.data = buffer;
      order[count % core] = ex.submit(() -> inline1(keys[count], ivs[count], tempdata)).get(); // order[count]

      if (count % core == core - 1) {
        ex.shutdown();
        ex = Executors.newFixedThreadPool(core);
        for (int j = 0; j < core; j++) {
          write[count - core + 1 + j] = order[j];
          bytearray tempiv = new bytearray();
          tempiv.data = Arrays.copyOfRange(write[count - core + 1 + j].data, 131056, 131072);
          ivs[count - core + 1 + j] = tempiv;
        }
      }

      if (count == 31) {
        for (int j = 0; j < 32; j++) {
          System.arraycopy(write[j].data, 0, tempwrite, 131072 * j, 131072);
        }
        f.write(tempwrite);
        count = -1;
        Arrays.fill(order, voidarray);
        Arrays.fill(write, voidarray);
      }
      count = count + 1;
    }

    if (chunknum0 % core != 0) {
      ex.shutdown();
      for (int i = 0; i < chunknum0 % core; i++) {
        write[(int) (count - (chunknum0 % core) + i)] = order[i];
        bytearray tempiv = new bytearray();
        tempiv.data = Arrays.copyOfRange(write[(int) (count - (chunknum0 % core) + i)].data, 131056, 131072);
        ivs[(int) (count - (chunknum0 % core) + i)] = tempiv;
      }
    }
    if (chunknum0 % 32 != 0) {
      bytearray tempdata = new bytearray(0);
      tempdata.data = write[0].data;
      for (int i = 1; i < 32; i++) {
        if (write[i].data != null) {
          tempdata.addByteBack(write[i].data);
        }
      }
      f.write(tempdata.data);
    }

    buffer = new byte[(int) chunknum1];
    t.read(buffer);
    bytearray lastwrite = new bytearray();
    lastwrite.data = padding(buffer);
    lastwrite = inline1(keys[count], ivs[count], lastwrite);
    f.write(lastwrite.data);

    t.close();
    f.close();
  }

  // short decryption no padding, 16B * n
  bytearray inline2(bytearray key, bytearray iv, bytearray indata) throws Exception {
    Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
    SecretKeySpec secretKey = new SecretKeySpec(key.data, "AES");
    IvParameterSpec ivSpec = new IvParameterSpec(iv.data);
    cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
    bytearray out = new bytearray();
    out.data = cipher.doFinal(indata.data);
    return out;
  }

  // decrypt(file) -> tempkaesl, n process
  void decryptn(String target, String pw, int core) throws Exception { // target : file path, pw : str
    FileInputStream f = new FileInputStream(target);
    byte[] buffer = new byte[4];
    f.read(buffer);
    buffer = new byte[2];
    f.read(buffer);
    int hintnum = (buffer[0] & 0xFF) + (buffer[1] & 0xFF) * 256;
    byte[] hintbyte = new byte[hintnum];
    f.read(hintbyte);
    buffer = new byte[32];
    f.read(buffer);
    bytearray saltbyte = new bytearray();
    saltbyte.data = buffer; // salt bytearray 32B
    buffer = new byte[32];
    f.read(buffer);
    bytearray pwhash = new bytearray();
    pwhash.data = buffer; // pwhash bytearray 32B
    buffer = new byte[128];
    f.read(buffer);
    bytearray ckeydata = new bytearray();
    ckeydata.data = buffer; // ckeydata bytearray 128B
    buffer = new byte[16];
    f.read(buffer);
    bytearray iv = new bytearray();
    iv.data = buffer; // iv bytearray 128B

    MessageDigest digest = MessageDigest.getInstance("SHA3-256");
    bytearray mkey = new bytearray(pw); // master key bytearray
    for (int i = 0; i < 10000; i++) {
      mkey.addByteBack(saltbyte.data);
      mkey.data = digest.digest(mkey.data);
    }

    bytearray enckey = new bytearray();
    bytearray enciv = new bytearray();
    enckey.data = Arrays.copyOfRange(mkey.data, 16, 32);
    enciv.data = Arrays.copyOfRange(mkey.data, 0, 16);
    bytearray ckey = inline2(enckey, enciv, ckeydata); // content key bytearray

    bytearray[] keys = expandkey(ckey); // 16B * 32 keys bytearray[]
    bytearray[] ivs = new bytearray[32];
    Arrays.fill(ivs, iv); // 16B * 32 ivs bytearray[]
    File file = new File(target);
    long filesize = file.length() - hintnum - 214; // actual file size
    long chunknum0 = filesize / 131072; // chunk num
    long chunknum1 = filesize % 131072; // left size
    if (chunknum1 == 0) {
      chunknum0 = chunknum0 - 1;
      chunknum1 = 131072;
    }

    FileOutputStream t = new FileOutputStream("tempkaesl");
    bytearray[] order = new bytearray[core];
    bytearray[] write = new bytearray[32];
    ex = Executors.newFixedThreadPool(core);
    count = 0; // iv, key position
    bytearray voidarray = new bytearray(0);
    Arrays.fill(order, voidarray);
    Arrays.fill(write, voidarray);

    buffer = new byte[131072];
    byte[] tempwrite = new byte[4194304];
    for (long i = 0; i < chunknum0; i++) {
      f.read(buffer); // 128kb
      bytearray tempdata = new bytearray();
      tempdata.data = buffer;
      order[count % core] = ex.submit(() -> inline2(keys[count], ivs[count], tempdata)).get(); // order[count]
      bytearray tempiv = new bytearray();
      tempiv.data = Arrays.copyOfRange(tempdata.data, 131056, 131072);
      ivs[count] = tempiv;

      if (count % core == core - 1) {
        ex.shutdown();
        ex = Executors.newFixedThreadPool(core);
        for (int j = 0; j < core; j++) {
          write[count - core + 1 + j] = order[j];
        }
      }

      if (count == 31) {
        for (int j = 0; j < 32; j++) {
          System.arraycopy(write[j].data, 0, tempwrite, 131072 * j, 131072);
        }
        t.write(tempwrite);
        count = -1;
        Arrays.fill(order, voidarray);
        Arrays.fill(write, voidarray);
      }
      count = count + 1;
    }

    if (chunknum0 % core != 0) {
      ex.shutdown();
      for (int i = 0; i < chunknum0 % core; i++) {
        write[(int) (count - (chunknum0 % core) + i)] = order[i];
      }
    }
    if (chunknum0 % 32 != 0) {
      bytearray tempdata = new bytearray(0);
      tempdata.data = write[0].data;
      for (int i = 1; i < 32; i++) {
        if (write[i].data != null) {
          tempdata.addByteBack(write[i].data);
        }
      }
      t.write(tempdata.data);
    }

    buffer = new byte[(int) chunknum1];
    f.read(buffer);
    bytearray lastwrite = new bytearray();
    lastwrite.data = buffer;
    lastwrite = inline2(keys[count], ivs[count], lastwrite);
    lastwrite.data = unpadding(lastwrite.data);
    t.write(lastwrite.data);

    t.close();
    f.close();
  }

  // valid pw check
  boolean check(byte[] salt, String pw, byte[] pwhash) throws Exception {
    MessageDigest digest = MessageDigest.getInstance("SHA3-256");
    bytearray newhash = new bytearray(pw); // new pwh bytearray
    for (int i = 0; i < 100000; i++) {
      newhash.addByteFront(salt);
      newhash.data = digest.digest(newhash.data);
    }
    return Arrays.equals(pwhash, newhash.data);
  }

  // valid file check, get pwhs
  bytearray[] view(String target) throws Exception { // target : file path
    bytearray[] out = new bytearray[4];
    FileInputStream f = new FileInputStream(target);
    byte[] buffer = new byte[4];
    f.read(buffer);
    if (Arrays.equals(buffer, new byte[] { 79, 84, 69, 49 })) {
      bytearray b0 = new bytearray();
      b0.data = new byte[] { 0 };
      out[0] = b0; // validity flag

      buffer = new byte[2];
      f.read(buffer);
      int hintnum = (buffer[0] & 0xFF) + (buffer[1] & 0xFF) * 256;
      buffer = new byte[hintnum];
      f.read(buffer);
      bytearray b1 = new bytearray();
      b1.data = buffer;
      out[1] = b1; // msg bytearray

      buffer = new byte[32];
      f.read(buffer);
      bytearray b2 = new bytearray();
      b2.data = buffer; // salt bytearray 32B
      out[2] = b2;

      buffer = new byte[32];
      f.read(buffer);
      bytearray b3 = new bytearray();
      b3.data = buffer; // pwhash bytearray 32B
      out[3] = b3;

    } else {
      bytearray b0 = new bytearray();
      b0.data = new byte[] { 1 };
      out[0] = b0;
    }
    f.close();
    return out;
  }

  // main engine
  String mainengine(String[] enfiles, String defile, String outputPath, String msg, String pw, int core) {
    String stout;

    try {
      if (enfiles.length != 0) {
        dozip(enfiles);
        encryptn(msg, pw, outputPath, core);
        Files.delete(Paths.get("./tempkaesl"));
        stout = "complete : " + outputPath;

      } else {
        if (defile.length() != 0) {
          bytearray[] res = view(defile);
          if (res[0].data[0] == 0) {
            if (check(res[2].data, pw, res[3].data)) {
              decryptn(defile, pw, core);
              unzip(outputPath);
              Files.delete(Paths.get("./tempkaesl"));
              stout = "complete : " + outputPath;
            } else {
              stout = "complete : Not Valid PW";
            }
          } else {
            stout = "complete : Not Valid OTE";
          }

        } else {
          stout = "complete : Nothing";
        }
      }

    } catch (Exception e) {
      stout = "error : " + e.toString();
    }
    return stout;
  }
}

// yas_java.java
public class yas_java {
  engine k = new engine();
  public int core = 8;
  public String msg = "YAS java crypto module";
  
  public String Encrypt(String[] files, String result, String pw) { // zip files, encrypt, move to result
    return this.k.mainengine(files, "", result, this.msg, pw, this.core);
  }

  public String Decrypt(String file, String unpackDir, String pw) { // decrypt file, unzip to unpackDir
    return this.k.mainengine(new String[] {}, file, unpackDir, "", pw, this.core);
  }

  public String View(String file) { // view file msg
    try {
      bytearray[] res = this.k.view(file);
      if (res[0].data[0] == 0) {
        return new String(res[1].data, StandardCharsets.UTF_8);
      } else {
        return "error : Not Valid OTE";
      }
    } catch (Exception e) {
      return "error : " + e.toString();
    }
  }
}
