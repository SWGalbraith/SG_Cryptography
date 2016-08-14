package com.galbraith.security.encryption;

import javax.crypto.SecretKey;

/**
 *
 * @author Sean Galbraith
 */
public interface ICrypto {

    /**
     * Generates a new AES-256 encryption key. 
     * 
     * @return SecretKey - The new Encryption key.
     * @throws Exception
     */
    SecretKey getNewEncryptionKey() throws Exception;
    
    /**
     * Gets a new SecretKey object from a byte[] representation of a 256 bit Encryption Key.
     * 
     * @param keyBytes The byte[] representation of the Encryption Key.
     * @return 
     */
    SecretKey getEncryptionKeyFromBytes(byte[] keyBytes) throws Exception;
    
    /**
     * Encrypts a String with the AES Algorithm using a SecretKey.
     * 
     * @param unencryptedData The String to encrypt.
     * @param key The key used to encrypt the String.
     * @param randomisationSeed The seed number used to randomise the data after encryption.
     * @return String - The encrypted String.
     * @throws Exception
     */
    String encrypt(String unencryptedData, SecretKey key, int randomisationSeed) 
            throws Exception;
    
    /**
     * Decrypts an Encrypted String with the AES Algorithm using the SecretKey used to Encrypt it.
     * @param encryptedData The encrypted String.
     * @param key The key that was used to encrypt the String.
     * @param randomisationSeed The seed number used to randomise the data before decryption.
     * @return String - The decrypted String.
     * @throws Exception
     */
    String decrypt(String encryptedData, SecretKey key, int randomisationSeed) throws Exception;
    
    /**
     * Convert a byte[] to a Base64 String.
     * 
     * @param bytes The bytes to convert to a Base64 String.
     * @return String - The Base64 representation of the byte[].
     */
    String bytesToBase64(byte[] bytes);
    
    /**
     * Convert a Base64 String to a byte[].
     * 
     * @param base64String The Base64 String to convert to a byte[].
     * @return byte[] - The byte[] representation of the Base64 String.
     */
    byte[] base64ToBytes(String base64String);

}
