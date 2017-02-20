/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package fileprotector.decrypt;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.PrivateKey;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;

/**
 *
 * @author Yasin Radi
 */
public class Decrypter {
    
    public byte[] decryptData(SecretKey sKey, byte[] data) {
        byte[] decryptedData = null;
        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, sKey);
            decryptedData = cipher.doFinal(data);
        } catch (Exception ex) {
            System.err.println("Decrypting error: " + ex);
        }
        return decryptedData;
    }
    
    public byte[] decryptWrappedData(byte[] data, byte[] key, PrivateKey pk) {
        byte[] decWrappedData = null;
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.UNWRAP_MODE, pk);  
            SecretKey sKey = (SecretKey) cipher.unwrap(key, "AES", Cipher.SECRET_KEY);
            cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, sKey);
            decWrappedData = cipher.doFinal(data);
        } catch (Exception ex) {
            System.err.println("Descrypting error: " + ex);
        }
        return decWrappedData;
    }

    public byte[] readData(File f) {

        FileInputStream fis = null;
        byte[] decrypt1 = new byte[(int) f.length()];
        try {
            fis = new FileInputStream(f);
            fis.read(decrypt1);
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            try {
                if (fis != null) {
                    fis.close();
                }
            } catch (IOException ex) {
                ex.printStackTrace();
            }
        }
        return decrypt1;
    }

    public byte[] readKey() {

        File f = new File("k.rsa");
        FileInputStream fis = null;
        byte[] decryptKey = new byte[(int) f.length()];
        try {
            fis = new FileInputStream(f);
            fis.read(decryptKey);
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            try {
                if (fis != null) {
                    fis.close();
                }
            } catch (IOException ex) {
                ex.printStackTrace();
            }
        }
        return decryptKey;
    }
}
