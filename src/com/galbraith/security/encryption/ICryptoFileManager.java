package com.galbraith.security.encryption;

import java.io.IOException;
import javax.crypto.SecretKey;

/**
 *
 * @author Sean Galbraith
 */
public interface ICryptoFileManager {

    /**
     * Creates a secure CryptoInfo file to store Cryptography Info.
     * Only one key can be stored at a time, unless the filepath is specified.
     * Creating a new file at the same location will overwrite the previous file.
     * 
     * @param key The Encryption Key to store in the CryptoInfo file.
     * @param password The password used to secure the information in the CryptoInfo file
     * (This will be encrypted as part of the storage process)
     * @param seed The Crypto Randomisation seed.
     * @throws Exception
     */
    void createCryptoInfoFile(SecretKey key, String password, int seed) throws Exception;

    /**
     * Creates a secure CryptoInfo file to store an Encryption Key.
     * Several keys can be stored at a time by specifying different filepaths
     * for each CryptoInfo file.
     * Creating a new file at the same location will overwrite the previous file.
     * 
     * @param filepath The path to the file to be created.
     * @param key The Encryption Key to store in the CryptoInfo file.
     * @param password The password used to secure the information in the CryptoInfo file
     * (This will be encrypted as part of the storage process)
     * @param seed The Crypto Randomisation seed.
     * @throws Exception
     */
    void createCryptoInfoFile(String filepath, SecretKey key, String password, int seed) throws Exception;
    
    /**
     * Removes the CryptoInfo file from the default location.
     * 
     * @throws IOException
     */
    void removeCryptoInfoFile() throws IOException;
    
    /**
     * Removes the CryptoInfo file from a specified filepath.
     * 
     * @param filepath - The path to the CryptoInfo file to be removed.
     * @throws IOException
     */
    void removeCryptoInfoFile(String filepath) throws IOException;
    
    /**
     * Retrieves the Stored Encryption Key from the default CryptoInfo file for 
     * use in Encryption/Decryption operations.
     * 
     * @param password The password to unlock the Stored Encryption Key.
     * @return SecretKey - The Stored Encryption Key.
     * @throws Exception 
     */
    SecretKey getStoredEncryptionKey(String password) throws Exception;
    
    /**
     * Retrieves the Stored Encryption Key from a CryptoInfo file for use in 
     * Encryption/Decryption operations.
     * 
     * @param filepath The path to the CryptoInfo file.
     * @param password The password to unlock the Stored Encryption Key.
     * @return SecretKey - The Stored Encryption Key.
     * @throws Exception 
     */
    SecretKey getStoredEncryptionKey(String filepath, String password) throws Exception;
    
    /**
     * Retrieves the Stored Randomisation Seed from the default CryptoInfo file.
     * 
     * @param password The password to unlock the Stored Crypto Seed.
     * @return int - The Stored Randomisation Seed.
     * @throws Exception 
     */
    int getStoredCryptoSeed(String password) throws Exception;
    
    /**
     * Retrieves the Stored Randomisation Seed from the specified CryptoInfo file.
     * 
     * @param filepath The path to the CryptoInfo file.
     * @param password The password to unlock the Stored Crypto Seed.
     * @return int - The Stored Randomisation Seed.
     * @throws Exception 
     */
    public int getStoredCryptoSeed(String filepath, String password) throws Exception;
    
    /**
     * Updates the Stored Crypto Password in the default CryptoInfo file with a new password.
     * 
     * @param oldPassword The current (unencrypted) Stored Crypto Password.
     * @param newPassword The new Stored Crypto Password. 
     * (This will be encrypted as part of the storage process)
     * @throws Exception 
     */
    void updateStoredCryptoPassword(String oldPassword, String newPassword)
            throws Exception;
    
    /**
     * Updates the Stored Crypto Password in the specified CryptoInfo file with a new password. 
     * 
     * @param filepath The path to the CryptoInfo file.
     * @param oldPassword The current (unencrypted) Stored Crypto Password.
     * @param newPassword The new Stored Crypto Password. 
     * (This will be encrypted as part of the storage process)
     * @throws Exception 
     */
    void updateStoredCryptoPassword(String filepath, String oldPassword, String newPassword)
            throws Exception;
    
    /**
     * Checks whether or not a given password matches Crypto Password stored in 
     * the default Crypto Info file.
     * 
     * @param password The password to be validated against the stored password.
     * @throws Exception 
     */
    boolean validateCryptoPassword(String password)
            throws Exception;
    
    /**
     * Checks whether or not a given password matches the Crypto Password stored
     * at the given filepath.
     * 
     * @param filepath The path to the CryptoInfo file.
     * @param password The password to be validated against the stored password.
     * @throws Exception 
     */
    boolean validateCryptoPassword(String filepath, String password)
            throws Exception;
    
    /**
     * Checks whether or not a Crypto Info file exists at the default location.
     * 
     * @return 
     */
    boolean doesCryptoInfoFileExist();
    
    /**
     * Checks whether or not a Crypto Info file exists at the given path.
     * 
     * @param filepath The filepath to check for a Crypto Info file
     * @return 
     */
    boolean doesCryptoInfoFileExist(String filepath);
}
