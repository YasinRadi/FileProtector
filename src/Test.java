
import fileprotector.decrypt.Decrypter;
import fileprotector.encrypt.Encrypter;
import fileprotector.utils.Utils;
import filprotector.exceptions.EncryptingException;
import java.security.PublicKey;
import java.util.Base64;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/**
 *
 * @author Yasin Radi
 */
public class Test {
    
    public static void main(String[] args) throws EncryptingException, Exception
    {
        Encrypter t = new Encrypter();
        Decrypter d = new Decrypter();
        String h = "Hello";
        
        byte[][] encData = t.encryptWrappedData(Utils.stringToByte(h), Utils.getCertificate().getPublicKey());
        byte[] data = encData[1];
        byte[] key = encData[0];
        
        byte[] encoded = Base64.getEncoder().encode(data);
        
        String dataString = Utils.byteToString(encoded);
        
        byte[] bytes = Utils.stringToByte(dataString);
        
        byte[] decoded = Base64.getDecoder().decode(bytes);
        
        byte[] dec = d.decryptWrappedData(decoded, key, Utils.getKey());
        
        System.out.println(Utils.byteToString(dec));
        
    }
}
