/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package fileprotector.decrypt;

import filprotector.exceptions.DecryptingException;
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
    
    public void decrypt(File fileToDecrypt, String password) throws DecryptingException
    {        
        /**
         * Gets the file name.
         */
        String[] fullFileName = fileToDecrypt.getName().split("\\.");
        String fileExtension  = fullFileName[fullFileName.length - 1];
        String fileName       = fileToDecrypt.getName()
                .substring(0, fileToDecrypt.getName().length() - (fileExtension.length() + 1));
        
        /**
         * Extension and original Path file.
         */
        File extFile       = new File(FileProtector.CONFIG_PATH + fileName + "Ext.bin");
        
        /**
         * Get original file extension from extension file.
         */
        String ext         = readExtFile(extFile).split(";")[0];
        
        /**
         * Get original file absolute path from extension file.
         */
        String origPath    = readExtFile(extFile).split(";")[1];
        if(origPath.contains("\\.")) origPath = origPath.replace("\\.", "");
        
        /**
         * Key file.
         */
        File keyFile       = new File(FileProtector.CONFIG_PATH + fileName + "Key.rsa");
        
        /**
         * Decrypted destination file.
         */
        File decryptedFile = new File(origPath + "." + ext); 
        
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
            
            /**
             * Delete meta files once decrypted.
             */
            keyFile.delete();
            extFile.delete();
            fileToDecrypt.delete();
        }
        catch(IOException e)
        {
            
        }
        catch(DecryptingException e)
        {
            throw new DecryptingException();
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
     * Uses a SecretKey to decrypt data.
     * @param sKey SecretKey
     * @param data byte[]
     * @return byte[]
     */
    public byte[] decryptData(SecretKey sKey, byte[] data) throws DecryptingException {
        byte[] decryptedData = null;
        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, sKey);
            decryptedData = cipher.doFinal(data);
        } catch (Exception ex) {
            throw new DecryptingException();
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
     * Reads the Path and Extension configuration file.
     * @param f File
     * @return String
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
