/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package fileprotector.encrypt;

import fileprotector.exceptions.EncryptingException;
import fileprotector.gui.FileProtector;
import fileprotector.utils.Utils;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

/**
 *
 * @author Yasin Radi
 */
public class Encrypter {
    
    /**
     * Encrypts a file given the file and a password.
     * @param originalFile  File
     * @param password      String
     * @throws FileNotFoundException
     * @throws IOException
     * @throws Exception 
     */
    public void encryptFile(File originalFile, String password) throws FileNotFoundException, IOException, Exception
    {    
        /**
         * File name & file extension.
         */
        String[] fullFileName = originalFile.getName().split("\\.");
        String fileExtension  = fullFileName[fullFileName.length - 1];
        String fileName       = originalFile.getName()
                .substring(0, originalFile.getName().length() - (fileExtension.length() + 1));
        
        /**
         * Encrypted Content File.
         */
        File encryptedFile    = new File(FileProtector.FILE_PATH + fileName + ".bin");
        
        /**
         * File Input Stream and Byte array that will hold file content.
         */
        FileInputStream fis   = null;
        byte[] fileContent    = new byte[(int) originalFile.length()];
        
        try {
            fis = new FileInputStream(originalFile);
            fis.read(fileContent);
            
            /**
             * Secret Key generation using user's password.
             */
            SecretKey key     = Utils.passwordKeyGeneration(password, 128);
            
            /**
             * First encryption using user's password.
             */
            byte[] passEncrypt= this.encryptData(key, fileContent);
            
            /**
             * Second encryption using wrapped key algorithm.
             */
            byte[][] wrapped  = this.encryptWrappedData(passEncrypt, Utils.getCertificate().getPublicKey());
            
            /**
             * Encode file data to be saved.
             */
            byte[] encodData  = Base64.getEncoder().encode(wrapped[1]);
            byte[] encodKey   = Base64.getEncoder().encode(wrapped[0]);
            byte[] encodExt   = Base64.getEncoder().encode(Utils.stringToByte(fileExtension));
            String dataString = Utils.byteToString(encodData);
            String keyString  = Utils.byteToString(encodKey);
            String extString  = Utils.byteToString(encodExt);
            
            /**
             * Write encrypted encoded data into file.
             */
            this.writeEncryptedContent(dataString, keyString, extString, encryptedFile);
        } catch (FileNotFoundException e) {
            throw new FileNotFoundException();
        } catch (IOException e) {
            throw new IOException();
        } catch (Exception e) {
            throw new Exception();
        } finally {
            try {
                if(fis != null) {
                    fis.close();
                }
            } catch (IOException e) {
                throw new Exception();
            }
        }
    }
    
    /**
     * Encrypts a byte array of data using an AES algorithm taking a SecretKey.
     * @param sKey  SecretKey
     * @param data  byte[]
     * @return  byte[]
     * @throws EncryptingException 
     */
    private byte[] encryptData(SecretKey sKey, byte[] data) throws EncryptingException 
    {
        byte[] encryptedData = null;
        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, sKey);
            encryptedData = cipher.doFinal(data);
        } catch (InvalidKeyException | NoSuchAlgorithmException 
                | NoSuchPaddingException | IllegalBlockSizeException
                | BadPaddingException ex) {
            throw new EncryptingException();
        }
        return encryptedData;
    }
    
    /**
     * Encrypts a byte array of data using a RSA algorithm taking a PublicKey.
     * @param data
     * @param pub
     * @return byte[][]
     * @throws EncryptingException 
     */
    public byte[][] encryptWrappedData(byte[] data, PublicKey pub) throws EncryptingException 
    {
        byte[][] encWrappedData = new byte[2][];
        try {
            KeyGenerator kgen = KeyGenerator.getInstance("AES");
            kgen.init(128);
            SecretKey sKey = kgen.generateKey();
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, sKey);
            byte[] encMsg = cipher.doFinal(data);
            cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.WRAP_MODE, pub);
            byte[] encKey = cipher.wrap(sKey);
            encWrappedData[0] = encKey;
            encWrappedData[1] = encMsg;
        } catch (InvalidKeyException | NoSuchAlgorithmException 
                | BadPaddingException | IllegalBlockSizeException 
                | NoSuchPaddingException ex) {
            throw new EncryptingException();
        }
        return encWrappedData;
    }

    /**
     * Write data into file.
     * @param data  String
     * @param key   String 
     * @param ext   String
     * @param f     File
     */
    private void writeEncryptedContent(String data, String key, String ext, File f) 
    {
        FileOutputStream fos = null;
        String encodedFile = data + ";" + key + ";" + ext;
        try {
            fos = new FileOutputStream(f);
            byte[] encData = Utils.stringToByte(encodedFile);
            if (!f.exists()) {
                f.createNewFile();
            }
            
            fos.write(encData);
            fos.flush();
            fos.close();
        } catch (IOException e) {
            Logger.getLogger(Encrypter.class.getName()).log(Level.SEVERE, null, e);
        } finally {
            try {
                if (fos != null) {
                    fos.close();
                }
            } catch (IOException e) {
                Logger.getLogger(Encrypter.class.getName()).log(Level.SEVERE, null, e);
            }
        }
    }    
}
