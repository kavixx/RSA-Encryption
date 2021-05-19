/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package rsa.algorithm;

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 *
 * @author Kavindu Thathsara
 */
public class RSAAlgorithm {

    private static final String PUBLIC_KEY_FILE = "Public.key";
    private static final String PRIVATE_KEY_FILE = "Private.key";
    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws IOException {
        // TODO code application logic here
        try{
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            KeyPair keypair = keyPairGenerator.generateKeyPair();
            PublicKey publicKey = keypair.getPublic();
            PrivateKey privateKey = keypair.getPrivate();
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            RSAPublicKeySpec rsaPublicKeySpec = keyFactory.getKeySpec(publicKey, RSAPublicKeySpec.class);
            RSAPrivateKeySpec rsaPrivateKeySpec = keyFactory.getKeySpec(privateKey, RSAPrivateKeySpec.class);
            
            RSAAlgorithm rsa = new RSAAlgorithm();
            rsa.saveKeys(PUBLIC_KEY_FILE, rsaPublicKeySpec.getModulus(), rsaPublicKeySpec.getPublicExponent());
            rsa.saveKeys(PRIVATE_KEY_FILE, rsaPrivateKeySpec.getModulus(), rsaPrivateKeySpec.getPrivateExponent());
            
            // Enter here message
            byte[] encryptedData = rsa.encrypt("We are learning RSA Algorithm");
            rsa.decrypt(encryptedData);
            
            
        }
        catch(NoSuchAlgorithmException | InvalidKeySpecException e){
            System.out.println(e);
        }
        
    }

    private void saveKeys(String fileName, BigInteger modulus, BigInteger Exponent) throws IOException{
        FileOutputStream fos = null;
        ObjectOutputStream oos = null;
        try{
            //System.out.println("  "+fileName);
            fos = new FileOutputStream(fileName);
            oos = new ObjectOutputStream(new BufferedOutputStream(fos));
            oos.writeObject(modulus);
            oos.writeObject(Exponent);
        }
        catch(Exception e){
            e.printStackTrace();
        }
        finally{
            if(oos != null){
                oos.close();
                if(fos != null){
                    fos.close();
                }
            }
        }
    }

    //message encrypted here
    private byte[] encrypt(String data) throws IOException{
        System.out.println(" "+data);
        byte[] dataToEncrypt = data.getBytes();
        byte[] encryptedData = null;
        try{
            PublicKey pubKey = readPublicKeyFromFile(this.PUBLIC_KEY_FILE);
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, pubKey);
            encryptedData = cipher.doFinal(dataToEncrypt);
            System.out.println("Encrypted data: "+encryptedData);
        }
        catch(NoSuchAlgorithmException | InvalidKeyException | IllegalBlockSizeException | NoSuchPaddingException | BadPaddingException e){
            e.printStackTrace();
        }
        return encryptedData;
         
    }
    //message decrypted here
    private void decrypt(byte[] data) throws IOException{
        byte [] descryptedData = null;
        try{
            PrivateKey privateKey = readPrivateKeyFromFile(this.PRIVATE_KEY_FILE);
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            descryptedData = cipher.doFinal(data);
            System.out.println("Decrypted data: "+new String (descryptedData));
                    
        }
        catch(NoSuchAlgorithmException | NoSuchPaddingException | BadPaddingException | IllegalBlockSizeException | InvalidKeyException e){
            
        }
    }
    //read the public key from file
    public PublicKey readPublicKeyFromFile(String fileName)throws IOException {
        FileInputStream fis = null;
        ObjectInputStream ois = null;
        try{
            fis = new FileInputStream(new File(fileName));
            ois = new ObjectInputStream(fis);
            BigInteger modulus = (BigInteger) ois.readObject();
            BigInteger Exponent = (BigInteger) ois.readObject();
            
            RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(modulus, Exponent);
            KeyFactory fact = KeyFactory.getInstance("RSA");
            PublicKey publicKey = fact.generatePublic(rsaPublicKeySpec);
            return publicKey;
        }
        catch(ClassNotFoundException | NoSuchAlgorithmException | InvalidKeySpecException e){
            e.printStackTrace();
        }
        finally{
            if(ois != null){
                ois.close();
                if(fis != null){
                    fis.close();
                }
            }
        }
        return null;
        
        }
    //read the private key from file
    public PrivateKey readPrivateKeyFromFile(String fileName)throws IOException {
    FileInputStream fis = null;
        ObjectInputStream ois = null;
        try{
            fis = new FileInputStream(new File(fileName));
            ois = new ObjectInputStream(fis);
            BigInteger modulus = (BigInteger) ois.readObject();
            BigInteger Exponent = (BigInteger) ois.readObject();
            
            RSAPrivateKeySpec rsaPrivateKeySpec = new RSAPrivateKeySpec(modulus, Exponent);
            KeyFactory fact = KeyFactory.getInstance("RSA");
            PrivateKey privateKey = fact.generatePrivate(rsaPrivateKeySpec);
            return privateKey;
        }
        catch(ClassNotFoundException | NoSuchAlgorithmException | InvalidKeySpecException e){
            e.printStackTrace();
        }
        finally{
            if(ois != null){
                ois.close();
                if(fis != null){
                    fis.close();
                }
            }
        }
        return null;
       
    }
}

