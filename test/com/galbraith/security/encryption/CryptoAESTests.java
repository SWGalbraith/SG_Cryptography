package com.galbraith.security.encryption;

import com.galbraith.security.encryption.CryptoAES;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 * Unit Test class for the CryptoAES class.
 * 
 * @author Sean Galbraith
 */
public class CryptoAESTests {

    // <editor-fold defaultstate="collapsed" desc="Test Setup">
    ICrypto crypto;
    
    public CryptoAESTests() {
        crypto = new CryptoAES();
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

    // <editor-fold defaultstate="collapsed" desc="base64ToBytes Tests">
    @Test
    public void base64ToBytesReturnsNullWhenNullHexStringProvided() {
        byte[] results = crypto.base64ToBytes(null);
        assertArrayEquals(results, null);
    }
    
    @Test
    public void base64ToBytesReturnsNullWhenEmptyHexStringProvided() {
        byte[] results = crypto.base64ToBytes("");
        assertArrayEquals(results, null);
    }
    
    @Test
    public void base64ToBytesThrowsExceptionWhenInvalidHexStringProvided() {
        boolean testPassed = false;
        
        try {
            crypto.base64ToBytes("¬¬¬¬¬¬¬¬¬¬¬");
        }
        catch (Exception ex) {
            testPassed = true;
        }
        
        assertTrue(testPassed);
    }
    
    @Test
    public void base64ToBytesReturnsCorrectBytesFromHexStringProvided() {
        byte[] expectedResults = new byte[] { 15, -73 };
        byte[] results = crypto.base64ToBytes("D7c=");
        assertArrayEquals(expectedResults, results);
    }
    // </editor-fold>
    
    // <editor-fold defaultstate="collapsed" desc="bytesToBase64 Tests">
    @Test
    public void bytesToBase64ReturnsNullWhenNullBytesArrayProvided() {
        String result = crypto.bytesToBase64(null);
        assertEquals(result, null);
    }
    
    @Test
    public void bytesToBase64ReturnsNullWhenEmptyBytesArrayProvided() {
        String result = crypto.bytesToBase64(new byte[0]);
        assertEquals(result, null);
    }
    
    @Test
    public void bytesToHexReturnsCorrectHexStringFromBytesArrayProvided() {
        String expectedResults = "D7c=";
        String results = crypto.bytesToBase64(new byte[] { 15, -73 });
        assertEquals(expectedResults, results);
    }
    // </editor-fold>
    
    // <editor-fold defaultstate="collapsed" desc="getEncryptionKeyFromBytes Tests">
    @Test
    public void getEncryptionKeyFromBytesReturnsSecretKeyWithBytesMatchingBytesProvided() throws Exception {
        byte[] keyBytes = new byte[] { -27, -121, 73, -63, -94, 109, 6, 74, -58, 
            -42, -75, 93, -3, -78, -104, -101, 23, 114, -93, -23, -95, -22, 77, 
            -113, -42, 109, -44, -60, -43, 72, 62, -113 };
        
        SecretKey expectedResult = new SecretKeySpec(keyBytes, 0, keyBytes.length, "AES");
        SecretKey result = crypto.getEncryptionKeyFromBytes(keyBytes);
        
        assertEquals(expectedResult, result);
    }
    
    @Test
    public void getEncryptionKeyFromBytesReturnsSecretKeyWithAESAlgorithm() throws Exception {
        byte[] keyBytes = new byte[] { -27, -121, 73, -63, -94, 109, 6, 74, -58, 
            -42, -75, 93, -3, -78, -104, -101, 23, 114, -93, -23, -95, -22, 77, 
            -113, -42, 109, -44, -60, -43, 72, 62, -113 };
        
        SecretKey result = crypto.getEncryptionKeyFromBytes(keyBytes);
        assertEquals("AES", result.getAlgorithm());
    }
    
    @Test
    public void getEncryptionKeyFromBytesThrowsExceptionWhenInvalidLengthArrayIsProvided() {
        boolean testPassed = false;
        
        try {
            byte[] keyBytes = new byte[] { -27, -121, 73 };
            crypto.getEncryptionKeyFromBytes(keyBytes);
        }
        catch (Exception ex) {
            testPassed = true;
        }
        
        assertTrue(testPassed);
    }
    // </editor-fold>
    
    // <editor-fold defaultstate="collapsed" desc="getNewEncryptionKey Tests">
    @Test
    public void getNewEncryptionKeyReturnsSecretKeyWithAESAlgorithm() throws Exception {
        SecretKey result = crypto.getNewEncryptionKey();
        assertEquals("AES", result.getAlgorithm());
    }
    
    @Test
    public void getNewEncryptionKeyReturnsSecretKeyWith256BitKey() throws Exception {
        SecretKey result = crypto.getNewEncryptionKey();
        assertEquals(32, result.getEncoded().length);
    }
    // </editor-fold>
    
    // <editor-fold defaultstate="collapsed" desc="encrypt Tests">
    @Test
    public void encryptThrowsExceptionWhenInvalidKeyLengthGiven() {
        boolean testPassed = false;
        
        try {
            byte[] keyBytes = new byte[] { -27, -121, 73 };
            SecretKey key = new SecretKeySpec(keyBytes, 0, keyBytes.length, "AES");
        
            crypto.encrypt("TEST", key, 256);
        }
        catch (Exception ex) {
            testPassed = true;
        }
        
        assertTrue(testPassed);
    }

    public void encryptThrowsExceptionWhenInvalidKeyAlgorithmGiven() {
        boolean testPassed = false;
        
        try {
            byte[] keyBytes = new byte[] { -27, -121, 73, -63, -94, 109, 6, 74, -58, 
                -42, -75, 93, -3, -78, -104, -101, 23, 114, -93, -23, -95, -22, 77, 
                -113, -42, 109, -44, -60, -43, 72, 62, -113 };
            SecretKey key = new SecretKeySpec(keyBytes, 0, keyBytes.length, "INVALID");
        
            crypto.encrypt("TEST", key, 256);
        }
        catch (Exception ex) {
            testPassed = true;
        }
        
        assertTrue(testPassed);
    }
    
    @Test
    public void encryptThrowsExceptionWhenNullDataGiven() {
        boolean testPassed = false;
        
        try {
            byte[] keyBytes = new byte[] { -27, -121, 73, -63, -94, 109, 6, 74, -58, 
                -42, -75, 93, -3, -78, -104, -101, 23, 114, -93, -23, -95, -22, 77, 
                -113, -42, 109, -44, -60, -43, 72, 62, -113 };
            SecretKey key = new SecretKeySpec(keyBytes, 0, keyBytes.length, "AES");
        
            crypto.encrypt(null, key, 256);
        }
        catch (Exception ex) {
            testPassed = true;
        }
        
        assertTrue(testPassed);
    }
    
    @Test
    public void encryptThrowsExceptionWhenEmptyDataGiven() {
        boolean testPassed = false;
        
        try {
            byte[] keyBytes = new byte[] { -27, -121, 73, -63, -94, 109, 6, 74, -58, 
                -42, -75, 93, -3, -78, -104, -101, 23, 114, -93, -23, -95, -22, 77, 
                -113, -42, 109, -44, -60, -43, 72, 62, -113 };
            SecretKey key = new SecretKeySpec(keyBytes, 0, keyBytes.length, "AES");
        
            crypto.encrypt("", key, 256);
        }
        catch (Exception ex) {
            testPassed = true;
        }
        
        assertTrue(testPassed);
    }
    
    @Test
    public void encryptReturnsEncryptedString() throws Exception {       
        byte[] keyBytes = new byte[] { -27, -121, 73, -63, -94, 109, 6, 74, -58, 
            -42, -75, 93, -3, -78, -104, -101, 23, 114, -93, -23, -95, -22, 77, 
            -113, -42, 109, -44, -60, -43, 72, 62, -113 };
        SecretKey key = new SecretKeySpec(keyBytes, 0, keyBytes.length, "AES");
        
        String result = crypto.encrypt("TEST", key, 256);
        
        assertNotEquals(result, "TEST");
    }
    // </editor-fold>
    
    // <editor-fold defaultstate="collapsed" desc="decrypt Tests">
    @Test
    public void decryptThrowsExceptionWhenInvalidKeyLengthGiven() {
        boolean testPassed = false;
        
        try {
            byte[] keyBytes = new byte[] { -27, -121, 73 };
            SecretKey key = new SecretKeySpec(keyBytes, 0, keyBytes.length, "AES");
        
            crypto.decrypt("jVgC0nA==J6xJZxRKLjj91oq", key, 256);
        }
        catch (Exception ex) {
            testPassed = true;
        }
        
        assertTrue(testPassed);
    }

    public void decryptThrowsExceptionWhenInvalidKeyAlgorithmGiven() {
        boolean testPassed = false;
        
        try {
            byte[] keyBytes = new byte[] { -27, -121, 73, -63, -94, 109, 6, 74, -58, 
                -42, -75, 93, -3, -78, -104, -101, 23, 114, -93, -23, -95, -22, 77, 
                -113, -42, 109, -44, -60, -43, 72, 62, -113 };
            SecretKey key = new SecretKeySpec(keyBytes, 0, keyBytes.length, "INVALID");
        
            crypto.decrypt("jVgC0nA==J6xJZxRKLjj91oq", key, 256);
        }
        catch (Exception ex) {
            testPassed = true;
        }
        
        assertTrue(testPassed);
    }
    
    @Test
    public void decryptThrowsExceptionWhenNullDataGiven() {
        boolean testPassed = false;
        
        try {
            byte[] keyBytes = new byte[] { -27, -121, 73, -63, -94, 109, 6, 74, -58, 
                -42, -75, 93, -3, -78, -104, -101, 23, 114, -93, -23, -95, -22, 77, 
                -113, -42, 109, -44, -60, -43, 72, 62, -113 };
            SecretKey key = new SecretKeySpec(keyBytes, 0, keyBytes.length, "AES");
        
            crypto.decrypt(null, key, 256);
        }
        catch (Exception ex) {
            testPassed = true;
        }
        
        assertTrue(testPassed);
    }
    
    @Test
    public void decryptThrowsExceptionWhenEmptyDataGiven() {
        boolean testPassed = false;
        
        try {
            byte[] keyBytes = new byte[] { -27, -121, 73, -63, -94, 109, 6, 74, -58, 
                -42, -75, 93, -3, -78, -104, -101, 23, 114, -93, -23, -95, -22, 77, 
                -113, -42, 109, -44, -60, -43, 72, 62, -113 };
            SecretKey key = new SecretKeySpec(keyBytes, 0, keyBytes.length, "AES");
        
            crypto.decrypt("", key, 256);
        }
        catch (Exception ex) {
            testPassed = true;
        }
        
        assertTrue(testPassed);
    }
    
    @Test
    public void decryptReturnsDecryptedString() throws Exception {       
        byte[] keyBytes = new byte[] { -27, -121, 73, -63, -94, 109, 6, 74, -58, 
            -42, -75, 93, -3, -78, -104, -101, 23, 114, -93, -23, -95, -22, 77, 
            -113, -42, 109, -44, -60, -43, 72, 62, -113 };
        SecretKey key = new SecretKeySpec(keyBytes, 0, keyBytes.length, "AES");
        
        String result = crypto.decrypt("jVgC0nA==J6xJZxRKLjj91oq", key, 256);
        
        assertEquals(result, "TEST");
    }
    // </editor-fold>
}