/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package fileprotector.utils;

import fileprotector.decrypt.Decrypter;
import java.io.File;
import java.io.FileInputStream;
import java.io.UnsupportedEncodingException;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author Yasin Radi
 */
public class Utils {
    
    /**
     * Get the Key store.
     * @return KeyStore
     * @throws Exception 
     */
    public static KeyStore getKeyStore() throws Exception 
    {
        return loadKeyStore("source.jks", "password");
    }
    
    /**
     * Get the Certificate related to the Key Store.
     * @return Certificate
     * @throws Exception 
     */
    public static Certificate getCertificate() throws Exception 
    {
        return getKeyStore().getCertificate("source");
    }
    
    /**
     * Get the Key Store Private Key.
     * @return PrivateKey
     * @throws Exception 
     */
    public static PrivateKey getKey() throws Exception
    {
        return (PrivateKey) getKeyStore().getKey("source", "password".toCharArray());
    } 
    
    /**
     * Loads the Key Store.
     * @param ksFile KeyStore path
     * @param ksPwd KeyStore password
     * @return KeyStore
     * @throws Exception 
     */
    public static KeyStore loadKeyStore(String ksFile, String ksPwd) throws Exception {
        KeyStore ks = KeyStore.getInstance("JCEKS");
        File f = new File(ksFile);
        if (f.isFile()) {
            FileInputStream in = new FileInputStream(f);
            ks.load(in, ksPwd.toCharArray());
        }
        return ks;
    }
    
    /**
     * Generates a SecretKey using the inputed password.
     * @param password password
     * @param keySize SecretKey size
     * @return SecretKey
     */
    public static SecretKey passwordKeyGeneration(String password, int keySize) {
        SecretKey sKey = null;
        if ((keySize == 128) || (keySize == 192) || (keySize == 256)) {
            try {
                byte[] data = password.getBytes("UTF-8");
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                byte[] hash = md.digest(data);
                byte[] key = Arrays.copyOf(hash, keySize / 8);
                sKey = new SecretKeySpec(key, "AES");
            } catch (Exception ex) {
                System.err.println("Key generation error:" + ex);
            }
        }
        return sKey;
    }
    
    /**
     * Converts a byte[] into its String equivalent.
     * @param arr byte[]
     * @return String
     */
    public static String byteToString(byte[] arr) {
        String str = null;
        try {
            str = new String(arr, "UTF-8");
        } catch (UnsupportedEncodingException ex) {
            Logger.getLogger(Decrypter.class.getName()).log(Level.SEVERE, null, ex);
        }
        return str;
    }
    
    /**
     * Converts a String into its byte[] equivalent.
     * @param data String
     * @return byte[]
     */
    public static byte[] stringToByte(String data) {
        byte[] bArray = data.getBytes();
        return bArray;
    }
    
    /**
     * Checks if the input password and the confirm password are equal.
     * @param pass String
     * @param confirm String
     * @return boolean
     */
    public static boolean passwordCheck(String pass, String confirm)
    {
        return pass.equals(confirm);
    }
    
    /**
     * Converts a char[] into String.
     * @param array char[]
     * @return String
     */
    public static String charArrayToString(char[] array)
    {
        return new String(array);
    }
}
