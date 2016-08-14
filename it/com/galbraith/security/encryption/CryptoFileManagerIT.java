package com.galbraith.security.encryption;

import com.galbraith.security.encryption.CryptoFileManager;
import com.galbraith.security.encryption.CryptoAES;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 * Integration Test class for the CryptoFileManager class.
 * 
 * @author Sean Galbraith
 */
public class CryptoFileManagerIT {

    // <editor-fold defaultstate="collapsed" desc="Test Setup">
    ICryptoFileManager cryptoFileManager;
    SecretKey testKey;
    
    public CryptoFileManagerIT() {
        cryptoFileManager = new CryptoFileManager();
        
        byte[] keyBytes = new byte[] { -27, -121, 73, -63, -94, 109, 6, 74, -58, 
            -42, -75, 93, -3, -78, -104, -101, 23, 114, -93, -23, -95, -22, 77, 
            -113, -42, 109, -44, -60, -43, 72, 62, -113 };
        
        testKey = new SecretKeySpec(keyBytes, 0, keyBytes.length, "AES");
    }

    @BeforeClass
    public static void setUpClass() {
    }

    @AfterClass
    public static void tearDownClass() {
    }

    @Before
    public void setUp() {
    }

    @After
    public void tearDown() {
    }
    // </editor-fold>

    // <editor-fold defaultstate="collapsed" desc="createCryptoInfo without filename Tests">
    @Test
    public void createCryptoInfoFileCreatesFileInDefaultLocation() throws Exception {
        boolean testPassed = false;
        
        cryptoFileManager.createCryptoInfoFile(testKey, "2B=9ASZ8CvjNWLZq=mUpagA9", 11);
        
        String directoryPath = System.getProperty("user.dir") + File.separator + "security";
        String filepath = directoryPath + File.separator + "CryptoInfo.crp";
        
        File directory = new File(directoryPath);
        File file = new File(filepath);
        
        if (directory.exists() && file.exists()) {
            testPassed = true;
        }
        
        assertTrue(testPassed);
    }
    
    @Test
    public void createCryptoInfoFileCreatesFileInDefaultLocationWithEncryptedContents() throws Exception {
        boolean testPassed = false;
        
        cryptoFileManager.createCryptoInfoFile(testKey, "2B=9ASZ8CvjNWLZq=mUpagA9", 11);
        
        String directoryPath = System.getProperty("user.dir") + File.separator + "security";
        String filepath = directoryPath + File.separator + "CryptoInfo.crp";
        
        File directory = new File(directoryPath);
        File file = new File(filepath);
        
        if (directory.exists() && file.exists()) {
            String fileContent = readFile(filepath);
            
            String xmlCharacters = "<</>";
            CharSequence xmlOpenChar = xmlCharacters.subSequence(0, 0);
            CharSequence xmlendOpenChar = xmlCharacters.subSequence(1, 2);
            CharSequence xmlCloseChar = xmlCharacters.subSequence(3, 3);
            
            if (!fileContent.contains(xmlOpenChar) || 
                    !fileContent.contains(xmlendOpenChar) ||
                    !fileContent.contains(xmlCloseChar)) {
                testPassed = true;
            }
        }
        
        assertTrue(testPassed);
    }
    
    @Test
    public void createCryptoInfoFileCreatesFileInDefaultLocationWithCorrectEncryptedContents() throws Exception {
        boolean testPassed = false;
        
        cryptoFileManager.createCryptoInfoFile(testKey, "TEST_PASSWORD", 11);
        
        String directoryPath = System.getProperty("user.dir") + File.separator + "security";
        String filepath = directoryPath + File.separator + "CryptoInfo.crp";
        
        File directory = new File(directoryPath);
        File file = new File(filepath);
        
        if (directory.exists() && file.exists()) {            
            String fileContent = readFile(filepath);          
            String expectedFileContent = "+rLRjutH4XNXH1q//nPTWdHsk9+llpLUQ0dtAzpy1y712sXBFBReo0kiv2T7Y3Tqg7vHfcUYMfqu0/uX3qV951FwWhim86IDfJvPwnT+nNbpPbCS9Ylu0qUV1sw7m434ahfVD3FjcNwn3TnV=/xI7Cd5ZEOagbfOQd3HkFAusDVSoNOpJUhVMx3LvHIV2DPUf+uye2Sd4x3UfO0SS9jSUHMiA6QxBUWUgfXzRMuZn9HvJUytMUE/BBOXRZus+wWX9AdrAWEaoxA1GBWAVMSicDQx/MBbbkjxo6g/UXhhnrE0";
            
            if (fileContent.equals(expectedFileContent)) {
                testPassed = true;
            }
        }
        
        assertTrue(testPassed);
    }
    // </editor-fold>
    
    // <editor-fold defaultstate="collapsed" desc="createCryptoInfo with filename Tests">
    @Test
    public void createCryptoInfoFileCreatesFileInSpecifiedLocation() throws Exception {
        boolean testPassed = false;
        
        String directoryPath = System.getProperty("user.dir") + File.separator + "security_test";
        String filepath = directoryPath + File.separator + "CryptoInfo.crp";
        
        cryptoFileManager.createCryptoInfoFile(filepath, testKey, "2B=9ASZ8CvjNWLZq=mUpagA9", 11);
        
        File directory = new File(directoryPath);
        File file = new File(filepath);
        
        if (directory.exists() && file.exists()) {
            testPassed = true;
        }
        
        assertTrue(testPassed);
    }
    
    @Test
    public void createCryptoInfoFileCreatesFileInSpecifiedLocationWithEncryptedContents() throws Exception {
        boolean testPassed = false;
        
        String directoryPath = System.getProperty("user.dir") + File.separator + "security_test";
        String filepath = directoryPath + File.separator + "CryptoInfo.crp";
        
        cryptoFileManager.createCryptoInfoFile(filepath, testKey, "2B=9ASZ8CvjNWLZq=mUpagA9", 11);
        
        File directory = new File(directoryPath);
        File file = new File(filepath);
        
        if (directory.exists() && file.exists()) {
            String fileContent = readFile(filepath);
            
            String xmlCharacters = "<</>";
            CharSequence xmlOpenChar = xmlCharacters.subSequence(0, 0);
            CharSequence xmlendOpenChar = xmlCharacters.subSequence(1, 2);
            CharSequence xmlCloseChar = xmlCharacters.subSequence(3, 3);
            
            if (!fileContent.contains(xmlOpenChar) || 
                    !fileContent.contains(xmlendOpenChar) ||
                    !fileContent.contains(xmlCloseChar)) {
                testPassed = true;
            }
        }
        
        assertTrue(testPassed);
    }
    
    @Test
    public void createCryptoInfoFileCreatesFileInSpecifiedLocationWithCorrectEncryptedContents() throws Exception {
        boolean testPassed = false;
        
        String directoryPath = System.getProperty("user.dir") + File.separator + "security_test";
        String filepath = directoryPath + File.separator + "CryptoInfo.crp";
        
        cryptoFileManager.createCryptoInfoFile(filepath, testKey, "TEST_PASSWORD", 11);
        
        File directory = new File(directoryPath);
        File file = new File(filepath);
        
        if (directory.exists() && file.exists()) {            
            String fileContent = readFile(filepath);
            
            String expectedFileContent = "+rLRjutH4XNXH1q//nPTWdHsk9+llpLUQ0dtAzpy1y712sXBFBReo0kiv2T7Y3Tqg7vHfcUYMfqu0/uX3qV951FwWhim86IDfJvPwnT+nNbpPbCS9Ylu0qUV1sw7m434ahfVD3FjcNwn3TnV=/xI7Cd5ZEOagbfOQd3HkFAusDVSoNOpJUhVMx3LvHIV2DPUf+uye2Sd4x3UfO0SS9jSUHMiA6QxBUWUgfXzRMuZn9HvJUytMUE/BBOXRZus+wWX9AdrAWEaoxA1GBWAVMSicDQx/MBbbkjxo6g/UXhhnrE0";
            
            if (fileContent.equals(expectedFileContent)) {
                testPassed = true;
            }
        }
        
        assertTrue(testPassed);
    }
    // </editor-fold>
    
    // <editor-fold defaultstate="collapsed" desc="removeCryptoInfoFile without filename Tests">
    @Test
    public void removeCryptoInfoFileFromDefaultLocationSuccessfullyRemovesFile() throws Exception {
        
        String directoryPath = System.getProperty("user.dir") + File.separator + "security";
        String filepath = directoryPath + File.separator + "CryptoInfo.crp";
        
        cryptoFileManager.createCryptoInfoFile(testKey, "TEST_PASSWORD", 11);
        cryptoFileManager.removeCryptoInfoFile();
        
        File file = new File(filepath);
        
        assertFalse(file.exists());
    }
    // </editor-fold>
    
    // <editor-fold defaultstate="collapsed" desc="removeCryptoInfoFile with filename Tests">
    @Test
    public void removeCryptoInfoFileFromSpecifiedLocationThrowsExceptionWhenIncorrectFilepathGiven() throws Exception {
        boolean testPassed = false;
        
        String directoryPath = System.getProperty("user.dir") + File.separator + "security_test";
        String filepath = directoryPath + File.separator + "CryptoInfo.crp";
        
        cryptoFileManager.createCryptoInfoFile(filepath, testKey, "2B=9ASZ8CvjNWLZq=mUpagA9", 11);
        
        File directory = new File(directoryPath);
        File file = new File(filepath);
        
        if (directory.exists() && file.exists()) {
            String invalidDirectoryPath = System.getProperty("user.dir") + File.separator + "invalid_security_test";
            String invalidFilepath = invalidDirectoryPath + File.separator + "Invalid_CryptoInfo.crp";
            
            try {
                cryptoFileManager.removeCryptoInfoFile(invalidFilepath);
            }
            catch (Exception ex) {
                testPassed = true;
            }
        }        
        
        assertTrue(testPassed);
    }
    
    @Test
    public void removeCryptoInfoFileFromSpecifiedLocationSuccessfullyRemovesFile() throws Exception {
        
        String directoryPath = System.getProperty("user.dir") + File.separator + "security_test";
        String filepath = directoryPath + File.separator + "CryptoInfo.crp";
        
        cryptoFileManager.createCryptoInfoFile(filepath, testKey, "TEST_PASSWORD", 11);
        cryptoFileManager.removeCryptoInfoFile(filepath);
        
        File file = new File(filepath);
        
        assertFalse(file.exists());
    }
    // </editor-fold>
    
    // <editor-fold defaultstate="collapsed" desc="getStoredCryptoSeed without filename Tests">
    @Test
    public void getStoredCryptoSeedFromDefaultLocationThrowsExceptionWhenIncorrectPasswordGiven() throws Exception {
        boolean testPassed = false;
        
        try {
            cryptoFileManager.createCryptoInfoFile(testKey, "2B=9ASZ8CvjNWLZq=mUpagA9", 11);
            cryptoFileManager.getStoredCryptoSeed("INVALID_PASSWORD");
        }
        catch (Exception ex) {
            testPassed = true;
        }
        
        assertTrue(testPassed);
    }
    
    @Test
    public void getStoredCryptoSeedFromDefaultLocationReturnsCorrectSeed() throws Exception {        
        cryptoFileManager.createCryptoInfoFile(testKey, "TEST_PASSWORD", 101);
        int result = cryptoFileManager.getStoredCryptoSeed("TEST_PASSWORD");
        assertEquals(result, 101);
    }
    // </editor-fold>
    
    // <editor-fold defaultstate="collapsed" desc="getStoredCryptoSeed with filename Tests">
    @Test
    public void getStoredCryptoSeedFromSpecifiedLocationThrowsExceptionWhenIncorrectPasswordGiven() throws Exception {
        boolean testPassed = false;
        
        try {
            String directoryPath = System.getProperty("user.dir") + File.separator + "security_test";
            String filepath = directoryPath + File.separator + "CryptoInfo.crp";
            cryptoFileManager.createCryptoInfoFile(filepath, testKey, "2B=9ASZ8CvjNWLZq=mUpagA9", 11);
            cryptoFileManager.getStoredCryptoSeed(filepath, "INVALID_PASSWORD");
        }
        catch (Exception ex) {
            testPassed = true;
        }
        
        assertTrue(testPassed);
    }
    
    @Test
    public void getStoredCryptoSeedFromSpecifiedLocationThrowsExceptionWhenIncorrectFilepathGiven() throws Exception {
        boolean testPassed = false;
        
        try {
            String directoryPath = System.getProperty("user.dir") + File.separator + "security_test";
            String filepath = directoryPath + File.separator + "CryptoInfo.crp";
            cryptoFileManager.createCryptoInfoFile(filepath, testKey, "2B=9ASZ8CvjNWLZq=mUpagA9", 11);
            
            String invalidDirectoryPath = System.getProperty("user.dir") + File.separator + "invalid_security_test";
            String invalidFilepath = invalidDirectoryPath + File.separator + "Invalid_CryptoInfo.crp";
            cryptoFileManager.getStoredCryptoSeed(invalidFilepath, "TEST_PASSWORD");
        }
        catch (Exception ex) {
            testPassed = true;
        }
        
        assertTrue(testPassed);
    }
    
    @Test
    public void getStoredCryptoSeedFromSpecifiedLocationReturnsCorrectSeed() throws Exception {        
        String directoryPath = System.getProperty("user.dir") + File.separator + "security_test";
        String filepath = directoryPath + File.separator + "CryptoInfo.crp";
        
        cryptoFileManager.createCryptoInfoFile(filepath, testKey, "TEST_PASSWORD", 11);
        int result = cryptoFileManager.getStoredCryptoSeed(filepath, "TEST_PASSWORD");
        assertEquals(result, 11);
    }
    // </editor-fold>
    
    // <editor-fold defaultstate="collapsed" desc="getStoredEncryptionCryptoKey without filename Tests">
    @Test
    public void getStoredEncryptionCryptoKeyFromDefaultLocationThrowsExceptionWhenIncorrectPasswordGiven() throws Exception {
        boolean testPassed = false;
        
        try {
            cryptoFileManager.createCryptoInfoFile(testKey, "TEST_PASSWORD", 11);
            cryptoFileManager.getStoredEncryptionKey("INVALID_PASSWORD");
        }
        catch (Exception ex) {
            testPassed = true;
        }
        
        assertTrue(testPassed);
    }
    
    @Test
    public void getStoredEncryptionCryptoKeyFromDefaultLocationReturnsCorrectKey() throws Exception {        
        cryptoFileManager.createCryptoInfoFile(testKey, "TEST_PASSWORD", 11);
        SecretKey result = cryptoFileManager.getStoredEncryptionKey("TEST_PASSWORD");
        assertEquals(result, testKey);
    }
    // </editor-fold>
    
    // <editor-fold defaultstate="collapsed" desc="getStoredEncryptionCryptoKey with filename Tests">
    @Test
    public void getStoredEncryptionCryptoKeyFromSpecifiedLocationThrowsExceptionWhenIncorrectPasswordGiven() throws Exception {
        boolean testPassed = false;
        
        try {
            String directoryPath = System.getProperty("user.dir") + File.separator + "security_test";
            String filepath = directoryPath + File.separator + "CryptoInfo.crp";
            cryptoFileManager.createCryptoInfoFile(filepath, testKey, "2B=9ASZ8CvjNWLZq=mUpagA9", 11);
            cryptoFileManager.getStoredEncryptionKey(filepath, "INVALID_PASSWORD");
        }
        catch (Exception ex) {
            testPassed = true;
        }
        
        assertTrue(testPassed);
    }
    
    @Test
    public void getStoredEncryptionCryptoKeyFromSpecifiedLocationThrowsExceptionWhenIncorrectFilepathGiven() throws Exception {
        boolean testPassed = false;
        
        try {
            String directoryPath = System.getProperty("user.dir") + File.separator + "security_test";
            String filepath = directoryPath + File.separator + "CryptoInfo.crp";
            cryptoFileManager.createCryptoInfoFile(filepath, testKey, "TEST_PASSWORD", 11);
            
            String invalidDirectoryPath = System.getProperty("user.dir") + File.separator + "invalid_security_test";
            String invalidFilepath = invalidDirectoryPath + File.separator + "Invalid_CryptoInfo.crp";
            cryptoFileManager.getStoredEncryptionKey(invalidFilepath, "TEST_PASSWORD");
        }
        catch (Exception ex) {
            testPassed = true;
        }
        
        assertTrue(testPassed);
    }
    
    @Test
    public void getStoredEncryptionCryptoKeyFromSpecifiedLocationReturnsCorrectKey() throws Exception {        
        String directoryPath = System.getProperty("user.dir") + File.separator + "security_test";
        String filepath = directoryPath + File.separator + "CryptoInfo.crp";
        
        cryptoFileManager.createCryptoInfoFile(filepath, testKey, "TEST_PASSWORD", 11);
        SecretKey result = cryptoFileManager.getStoredEncryptionKey(filepath, "TEST_PASSWORD");
        assertEquals(result, testKey);
    }
    // </editor-fold>
    
    // <editor-fold defaultstate="collapsed" desc="updateStoredCryptoPassword without filename Tests">
    @Test
    public void updateStoredCryptoPasswordAtDefaultLocationThrowsExceptionWhenInvalidPasswordGiven() throws Exception {
        boolean testPassed = false;
        
        try {
            cryptoFileManager.createCryptoInfoFile(testKey, "2B=9ASZ8CvjNWLZq=mUpagA9", 11);
            cryptoFileManager.updateStoredCryptoPassword("INVALID_PASSWORD", "11F14EEABD3E6E6D5750D982AB5BE39CF05129D96CB4902A3F822C2546392440");
        }
        catch (Exception ex) {
            testPassed = true;
        }
        
        assertTrue(testPassed);
    }
    
    @Test
    public void updateStoredCryptoPasswordAtDefaultLocationSuccessfullyUpdatesPassword() throws Exception {        
        cryptoFileManager.createCryptoInfoFile(testKey, "TEST_PASSWORD", 11);
        cryptoFileManager.updateStoredCryptoPassword("TEST_PASSWORD", "UPDATED_PASSWORD");
        
        String directoryPath = System.getProperty("user.dir") + File.separator + "security";
        String filepath = directoryPath + File.separator + "CryptoInfo.crp";
        
        File directory = new File(directoryPath);
        File file = new File(filepath);
        
        String fileContent = "EMPTY";
        String expectedFileContent = "EXPECTED";
        
        if (directory.exists() && file.exists()) {            
            fileContent = readFile(filepath);         
            expectedFileContent = "+i4CWVd/N7uUoYHdRVBU4ZMaktrF1d+PdV4y9gnAXV69I/I46nk7F2KdXTaMfjiyOZGFFEf99svVX3XaQxrYgIxrnXi6mbQN0Nqwf+nP9S4LI1r05mbTdlcu6sE+YrTbCppAauB1eiNVUSfmTW8R1TlFu+7wT01j3uS33xxTc4ASiOHyR4dNHbT68uVZx0+IV18872uBeHk96UnC6i1s1vEolS1gaHXhsbSDS3IdivBHthk0Vpxey9LNfMXDLRrz+ZdDSVBuPWjfSkB/9bT8pMbz39g47RxaAuYkPFjpwlyyoGikHHHwqMvmr5XdhQfE";
        }
        
        assertEquals(fileContent, expectedFileContent);
    }
    // </editor-fold>
    
    // <editor-fold defaultstate="collapsed" desc="updateStoredCryptoPassword with filename Tests">
    @Test
    public void updateStoredCryptoPasswordAtSpecifiedLocationThrowsExceptionWhenInvalidPasswordGiven() throws Exception {
        boolean testPassed = false;
        
        try {
            String directoryPath = System.getProperty("user.dir") + File.separator + "security_test";
            String filepath = directoryPath + File.separator + "CryptoInfo.crp";
            cryptoFileManager.createCryptoInfoFile(filepath, testKey, "2B=9ASZ8CvjNWLZq=mUpagA9", 11);
            cryptoFileManager.updateStoredCryptoPassword(filepath, "INVALID_PASSWORD", "11F14EEABD3E6E6D5750D982AB5BE39CF05129D96CB4902A3F822C2546392440");
        }
        catch (Exception ex) {
            testPassed = true;
        }
        
        assertTrue(testPassed);
    }
    
    @Test
    public void updateStoredCryptoPasswordAtSpecifiedLocationThrowsExceptionWhenIncorrectFilepathGiven() throws Exception {
        boolean testPassed = false;
        
        try {
            String directoryPath = System.getProperty("user.dir") + File.separator + "security_test";
            String filepath = directoryPath + File.separator + "CryptoInfo.crp";
            cryptoFileManager.createCryptoInfoFile(filepath, testKey, "2B=9ASZ8CvjNWLZq=mUpagA9", 11);
            
            String invalidDirectoryPath = System.getProperty("user.dir") + File.separator + "invalid_security_test";
            String invalidFilepath = invalidDirectoryPath + File.separator + "Invalid_CryptoInfo.crp";
            cryptoFileManager.updateStoredCryptoPassword(invalidFilepath, "TEST_PASSWORD", "11F14EEABD3E6E6D5750D982AB5BE39CF05129D96CB4902A3F822C2546392440");
        }
        catch (Exception ex) {
            testPassed = true;
        }
        
        assertTrue(testPassed);
    }
    
    @Test
    public void updateStoredCryptoPasswordAtSpecifiedLocationSuccessfullyUpdatesPassword() throws Exception {
        boolean testPassed = false;
        
        String directoryPath = System.getProperty("user.dir") + File.separator + "security_test";
        String filepath = directoryPath + File.separator + "CryptoInfo.crp";
        
        cryptoFileManager.createCryptoInfoFile(filepath, testKey, "TEST_PASSWORD", 11);
        cryptoFileManager.updateStoredCryptoPassword(filepath, "TEST_PASSWORD", "UPDATED_PASSWORD");
        
        File directory = new File(directoryPath);
        File file = new File(filepath);
        
        String fileContent = "EMPTY";
        String expectedFileContent = "EXPECTED";
        
        if (directory.exists() && file.exists()) {            
            fileContent = readFile(filepath);         
            expectedFileContent = "+i4CWVd/N7uUoYHdRVBU4ZMaktrF1d+PdV4y9gnAXV69I/I46nk7F2KdXTaMfjiyOZGFFEf99svVX3XaQxrYgIxrnXi6mbQN0Nqwf+nP9S4LI1r05mbTdlcu6sE+YrTbCppAauB1eiNVUSfmTW8R1TlFu+7wT01j3uS33xxTc4ASiOHyR4dNHbT68uVZx0+IV18872uBeHk96UnC6i1s1vEolS1gaHXhsbSDS3IdivBHthk0Vpxey9LNfMXDLRrz+ZdDSVBuPWjfSkB/9bT8pMbz39g47RxaAuYkPFjpwlyyoGikHHHwqMvmr5XdhQfE";
        }
        
        assertEquals(fileContent, expectedFileContent);
    }
    // </editor-fold>
    
    // <editor-fold defaultstate="collapsed" desc="Private Utility Methods">    
    private String readFile(String filename) throws IOException {
        String fileContents = "";
        File file = new File(filename);
        FileReader fr = new FileReader(file);
        BufferedReader br = new BufferedReader(fr);        
        
        try {
            String line;
            while ((line = br.readLine()) != null) {
                fileContents += line;
            }
        }
        finally {
            fr.close();
            br.close();
        }
        
        return fileContents;
    }
    // </editor-fold>
}