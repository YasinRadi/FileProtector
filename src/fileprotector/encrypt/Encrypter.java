/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package fileprotector.encrypt;

import exceptions.EncryptingException;
import fileprotector.gui.FileProtector;
import fileprotector.utils.Utils;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.PublicKey;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

/**
 *
 * @author Yasin Radi
 */
public class Encrypter {
    
    public void encryptFile(File originalFile, String password) throws FileNotFoundException, IOException
    {    
        /**
         * File name, file extension and file absolute path.
         */
        String[] fullFileName = originalFile.getName().split("\\.");
        String fileExtension  = fullFileName[fullFileName.length - 1];
        System.out.println(fileExtension);
        
        String fileName       = originalFile.getName()
                .substring(0, originalFile.getName().length() - (fileExtension.length() + 1));
        System.out.println(fileName);
        
        String filePath       = originalFile.getAbsolutePath()
                .substring(0, originalFile.getAbsolutePath().length() - fileName.length());
        if(filePath.charAt(filePath.length() - 1) == '.') filePath = filePath.substring(0, filePath.length() - 1);
        System.out.println(filePath);
        
        /**
         * Encrypted Content File.
         */
        File encryptedFile    = new File(FileProtector.FILE_PATH + fileName + ".rsa");
        
        /**
         * Encrypted Key File.
         */
        File encryptedKey     = new File(FileProtector.CONFIG_PATH + fileName + "Key.rsa");
        
        /**
         * File that saves original file extension.
         */
        File fileExt          = new File(FileProtector.CONFIG_PATH + fileName + "Ext.bin");
        
        /**
         * File Input Stream and Byte array that will hold file content.
         */
        FileInputStream fis   = null;
        byte[] fileContent    = new byte[(int) originalFile.length()];
        
        try
        {
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
             * Encrypted Content writing on a new file.
             */
            this.writeEncryptedContent(wrapped, encryptedFile);
            
            /**
             * Wrapped algorithm key writing on a new key file.
             */
            this.writeEncryptedKey(wrapped, encryptedKey);
            
            /**
             * Write file extension and file absolute path into a file.
             */
            this.writeExtensionAndPath(fileExtension, filePath, fileExt);
            
            /**
             * Delete original file once encrypted.
             */
            if(originalFile.exists()) originalFile.delete();
        }
        catch (FileNotFoundException e)
        {
            throw new FileNotFoundException();
        }
        catch (IOException e)
        {
            throw new IOException();
        }
        catch (Exception e)
        {
            
        }
        finally
        {
            try
            {
                if(fis != null)
                {
                    fis.close();
                }
            }
            catch (IOException e)
            {}
        }
        
        
    }
    
    private byte[] encryptData(SecretKey sKey, byte[] data) throws EncryptingException {
        byte[] encryptedData = null;
        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, sKey);
            encryptedData = cipher.doFinal(data);
        } catch (Exception ex) {
            throw new EncryptingException();
        }
        return encryptedData;
    }
    
    private byte[][] encryptWrappedData(byte[] data, PublicKey pub) throws EncryptingException {
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
        } catch (Exception ex) {
            throw new EncryptingException();
        }
        return encWrappedData;
    }

    private void writeEncryptedContent(byte[][] encryptedData, File f) {
        FileOutputStream fos = null;
        try {
            fos = new FileOutputStream(f);

            if (!f.exists()) {
                f.createNewFile();
            }
            // 0 = Key 1 = Data
            fos.write(encryptedData[1]);
            fos.flush();
            fos.close();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            try {
                if (fos != null) {
                    fos.close();
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    private void writeEncryptedKey(byte[][] encryptedData, File f) {

        FileOutputStream fos = null;
        try {
            fos = new FileOutputStream(f);

            if (!f.exists()) {
                f.createNewFile();
            }
            // 0 = Key 1 = Data
            fos.write(encryptedData[0]);
            fos.flush();
            fos.close();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            try {
                if (fos != null) {
                    fos.close();
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
    
    private void writeExtensionAndPath(String extension, String path, File f)
    {
        FileOutputStream fos = null;
        String extAndPath    = extension + ";" + path;
        try {
            fos = new FileOutputStream(f);

            if (!f.exists()) {
                f.createNewFile();
            }

            fos.write(Utils.stringToByte(extAndPath));
            fos.flush();
            fos.close();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            try {
                if (fos != null) {
                    fos.close();
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
    
}
