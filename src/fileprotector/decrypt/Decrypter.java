/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package fileprotector.decrypt;

import fileprotector.gui.FileProtector;
import fileprotector.utils.Utils;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.PrivateKey;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;

/**
 *
 * @author Yasin Radi
 */
public class Decrypter {
    
    public void decrypt(String file, String password)
    {
        /**
         * File to decrypt.
         */
        File fileToDecrypt = new File(file);
        
        /**
         * Gets the file name.
         */
        String fileName    = fileToDecrypt.getName().split(".")[0];
        
        /**
         * Extension and original Path file.
         */
        File extFile       = new File(FileProtector.FILE_PATH + fileName + "Ext.bin");
        
        /**
         * Get original file extension from extension file.
         */
        String ext         = readExtFile(extFile).split(";")[0];
        
        /**
         * Get original file absolute path from extension file.
         */
        String origPath    = readExtFile(extFile).split(";")[1];
        
        /**
         * Key file.
         */
        File keyFile       = new File(FileProtector.FILE_PATH + fileName + "Key.rsa");
        
        /**
         * Decrypted destination file.
         */
        File decryptedFile = new File(origPath + fileName + ext); 
        
        /**
         * File Output Stream to write on end file.
         */
        FileOutputStream fos = null;
        
        
        try
        {
            fos = new FileOutputStream(decryptedFile);
            
            /**
             * Read fully encrypted data.
             */
            byte[] fullEncryptContent = readData(fileToDecrypt);
            
            /**
             * Read encryption key.
             */
            byte[] decryptionKey      = readData(keyFile);
            
            /**
             * Decrypt wrapped data.
             */
            byte[] unwrappedData      = decryptWrappedData(fullEncryptContent, decryptionKey, Utils.getKey());
            
            /**
             * Generate a key using password and fully decrypt data.
             */
            byte[] fullDecryptContent = decryptData(Utils.passwordKeyGeneration(password, 128), unwrappedData);
            
            /**
             * Write fully decrypted data into new file.
             */
            fos.write(fullDecryptContent);
            fos.flush();
            fos.close();
            
        }
        catch(IOException e)
        {
            
        }
        catch(Exception e)
        {
            
        }
        finally
        {
            try
            {
                if(fos != null)
                {
                    fos.close();
                }
            }
            catch(IOException e)
            {
                
            }
        }
    }
    
    /**
     * 
     * @param sKey
     * @param data
     * @return 
     */
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
    
    /**
     * Decrypts wrapped data using a byte[] key and a Private Key.
     * @param data Wrapped data
     * @param key byte[] key
     * @param pk PrivateKey
     * @return byte[] unwrapped data
     */
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

    /**
     * Read data from file.
     * @param f File
     * @return byte[] data
     */
    public byte[] readData(File f) {

        FileInputStream fis = null;
        byte[] data = new byte[(int) f.length()];
        try {
            fis = new FileInputStream(f);
            fis.read(data);
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
        return data;
    }
    
    /**
     * 
     * @param f
     * @return 
     */
    public String readExtFile(File f)
    {
        String ext          = "";
        FileInputStream fis = null;
        byte[] extension    = new byte[(int) f.length()];
        try {
            fis = new FileInputStream(f);
            fis.read(extension);
            
            ext = Utils.byteToString(extension);
            
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
        return ext;
    }
}
