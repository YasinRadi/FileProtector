/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package fileprotector.decrypt;

import fileprotector.encrypt.Encrypter;
import fileprotector.exceptions.DecryptingException;
import fileprotector.gui.FileProtector;
import fileprotector.utils.Utils;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

/**
 *
 * @author Yasin Radi
 */
public class Decrypter {
    
    /**
     * Decrypt a file given a password.
     * @param fileToDecrypt File
     * @param password      String
     * @throws DecryptingException 
     * @throws IOException
     */
    public void decrypt(File fileToDecrypt, String password) throws DecryptingException, IOException, Exception
    {        
        /**
         * Gets the file name.
         */
        String[] fullFileName = fileToDecrypt.getName().split("\\.");
        String fileExtension  = fullFileName[fullFileName.length - 1];
        String fileName       = fileToDecrypt.getName()
                .substring(0, fileToDecrypt.getName().length() - (fileExtension.length() + 1));
        
        /**
         * File Output Stream to write on end file.
         */
        FileOutputStream fos = null;   
        
        try {            
            
            byte[] encData      = readData(fileToDecrypt);
            String encString    = Utils.byteToString(encData);
            String[] enc        = encString.split(";");
            String dataString   = enc[0];
            String keyString    = enc[1];
            String extString    = enc[2];
            byte[] data         = Base64.getDecoder().decode(dataString);
            byte[] key          = Base64.getDecoder().decode(keyString);
            byte[] ext          = Base64.getDecoder().decode(extString);
            String extension    = Utils.byteToString(ext);
            
            
            /**
             * Decrypt wrapped data.
             */
            byte[] unwrappedData      = decryptWrappedData(data, key, Utils.getKey());
            
            /**
             * Generate a key using password and fully decrypt data.
             */
            byte[] fullDecryptContent = decryptData(Utils.passwordKeyGeneration(password, 128), unwrappedData);
            
            /**
             * Write fully decrypted data into new file.
             */
            fos = new FileOutputStream(new File(FileProtector.FILE_PATH + fileName + "." + extension));
            fos.write(fullDecryptContent);
            fos.flush();
            fos.close();
            
            /**
             * Delete meta files once decrypted.
             */
            fileToDecrypt.delete();
        } catch(IOException e) {
            throw new IOException();
        } catch(DecryptingException e) {
            throw new DecryptingException();
        } catch(Exception e) {
            throw new Exception();
        } finally {
            try {
                if(fos != null) {
                    fos.close();
                }
            } catch(IOException e) {
                throw new Exception();
            }
        }
    }
    
    /**
     * Uses a SecretKey to decrypt data.
     * @param sKey SecretKey
     * @param data byte[]
     * @throws DecryptingException
     * @return byte[]
     */
    public byte[] decryptData(SecretKey sKey, byte[] data) throws DecryptingException 
    {
        byte[] decryptedData = null;
        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, sKey);
            decryptedData = cipher.doFinal(data);
        } catch (InvalidKeyException | NoSuchAlgorithmException 
                | BadPaddingException | IllegalBlockSizeException 
                | NoSuchPaddingException ex) {
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
    public byte[] decryptWrappedData(byte[] data, byte[] key, PrivateKey pk) 
    {
        byte[] decWrappedData = null;
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.UNWRAP_MODE, pk);  
            SecretKey sKey = (SecretKey) cipher.unwrap(key, "AES", Cipher.SECRET_KEY);
            cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, sKey);
            decWrappedData = cipher.doFinal(data);
        } catch (InvalidKeyException | NoSuchAlgorithmException 
                | BadPaddingException | IllegalBlockSizeException 
                | NoSuchPaddingException ex) {
            Logger.getLogger(Decrypter.class.getName()).log(Level.SEVERE, null, ex);
        }
        return decWrappedData;
    }

    /**
     * Read data from file.
     * @param f File
     * @return byte[] data
     */
    public byte[] readData(File f) 
    {
        FileInputStream fis = null;
        byte[] data = new byte[(int) f.length()];
        try {
            fis = new FileInputStream(f);
            fis.read(data);
        } catch (IOException e) {
            Logger.getLogger(Encrypter.class.getName()).log(Level.SEVERE, null, e);
        } finally {
            if (fis != null) {
                try {
                    fis.close();
                } catch (IOException e) {
                    Logger.getLogger(Encrypter.class.getName()).log(Level.SEVERE, null, e);
                }
            }
        }
        return data;
    }
}
