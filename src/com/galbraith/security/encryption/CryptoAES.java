package com.galbraith.security.encryption;

import java.util.Random;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

/**
 * Provides methods to encrypt and decrypt using the AES-256 algorithm, as well 
 * as creating keys in the correct format for AES-256 cryptography operations.
 * 
 * @author Sean Galbraith
 */
public class CryptoAES implements ICrypto {

    private final String CRYPTO_ALGORITHM_NAME = "AES";
    
    private static enum CryptoOperation {
        ENCRYPT,
        DECRYPT
    }
    
    @Override
    public SecretKey getNewEncryptionKey() throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance(CRYPTO_ALGORITHM_NAME);
        generator.init(256); // The AES key size in number of bits
        SecretKey key = generator.generateKey();
        return key;
    }
    
    @Override
    public SecretKey getEncryptionKeyFromBytes(byte[] keyBytes) throws Exception {
        if (keyBytes.length == 32) {
            SecretKey key = new SecretKeySpec(keyBytes, 0, keyBytes.length, CRYPTO_ALGORITHM_NAME);
            return key;
        }
        else {
            throw new Exception("Bytes provided are not 256-bit! Bytes are not valid as a key!");
        }
    }
     
    @Override
    public String encrypt(String unencryptedData, SecretKey key, int randomisationSeed) 
            throws Exception {
        
        if (key.getAlgorithm().equals("AES") && key.getEncoded().length == 32 && 
                unencryptedData != null && unencryptedData.length() > 0) {
            byte[] encryptedBytes = performCryptoOperation(unencryptedData.getBytes(),
                key, CryptoOperation.ENCRYPT);
        
            String encryptedData = bytesToBase64(encryptedBytes);
            String randomisedData = randomiseData(encryptedData, randomisationSeed);
        
            return randomisedData;
        }
        else {
            throw new Exception("The given key must use the AES-256 Algorithm, " 
                    +  "and data to encrypt must not be empty!");
        }
    }
     
    @Override
    public String decrypt(String encryptedData, SecretKey key, int randomisationSeed) throws Exception {
        
        if (key.getAlgorithm().equals("AES") && key.getEncoded().length == 32 && 
                encryptedData != null && encryptedData.length() > 0) {
            String unrandomisedData = unRandomiseData(encryptedData, randomisationSeed);
            byte[] encryptedDataBytes = base64ToBytes(unrandomisedData);
            byte[] decryptedBytes = performCryptoOperation(encryptedDataBytes,
                key, CryptoOperation.DECRYPT);
        
            String decryptedData = new String(decryptedBytes);
        
            return decryptedData;
        }
        else {
            throw new Exception("The given key must use the AES-256 Algorithm, " 
                    +  "and data to decrypt must not be empty!");
        }
    }
    
    @Override
    public String bytesToBase64(byte[] bytes) {
        if (bytes != null && bytes.length > 0) {
            return DatatypeConverter.printBase64Binary(bytes);
        }
        else {
            return null;
        }
    }
    
    @Override
    public byte[] base64ToBytes(String base64String) {        
        if (base64String != null && base64String.length() > 0) {            
            return DatatypeConverter.parseBase64Binary(base64String);
        }
        else {
            return null;
        }
    }
    
    private byte[] performCryptoOperation(byte[] data, SecretKey key, 
            CryptoOperation operation) throws Exception {
        
        Cipher aesCipher = Cipher.getInstance(CRYPTO_ALGORITHM_NAME);
        
        if (operation.equals(CryptoOperation.ENCRYPT)) {
            aesCipher.init(Cipher.ENCRYPT_MODE, key);      
        }
        else if (operation.equals(CryptoOperation.DECRYPT)) {
            aesCipher.init(Cipher.DECRYPT_MODE, key);
        }
        else {
            throw new Exception("Invalid Crypto Operation Type!");
        }
        
        byte[] cryptoResult = aesCipher.doFinal(data);
        return cryptoResult;
    }
    
    private String randomiseData(String unrandomisedData, int seed) {
        int size = unrandomisedData.length();
        char[] chars = unrandomisedData.toCharArray();
        int[] exchanges = getRandomisationExchanges(size, seed);
        
        for(int i = size -1; i > 0; i--) {
            int n = exchanges[size - 1 - i];
            char tmp = chars[i];
            chars[i] = chars[n];
            chars[n] = tmp;
        }
        
        String randomisedData = new String(chars);
        
        return randomisedData;
    }
    
    private String unRandomiseData(String randomisedData, int seed) {
        int size = randomisedData.length();
        char[] chars = randomisedData.toCharArray();
        int[] exchanges = getRandomisationExchanges(size, seed);
        
        for(int i = 1; i < size; i++) {
            int n = exchanges[size - 1 - i];
            char tmp = chars[i];
            chars[i] = chars[n];
            chars[n] = tmp;
        }
        
        String unrandomisedData = new String(chars);
        
        return unrandomisedData;
    }
    
    private int[] getRandomisationExchanges(int size, int key) {
        int[] exchanges = new int[size - 1];
        Random random = new Random(key);
        
        for(int i = size - 1; i > 0; i--) {
            int n = random.nextInt(i + 1);
            exchanges[size - 1 - i] = n;
        }
        
        return exchanges;
    }    
}
