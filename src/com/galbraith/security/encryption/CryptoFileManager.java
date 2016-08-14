package com.galbraith.security.encryption;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.StringReader;
import java.io.StringWriter;
import java.io.Writer;
import javax.crypto.SecretKey;
import javax.naming.AuthenticationException;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.xml.sax.InputSource;

/**
 * File Management class providing methods for managing files associated with
 cryptography operations provided by the CryptoAES class.
 * 
 * @author Sean Galbraith
 */
public class CryptoFileManager implements ICryptoFileManager {

    private final String CRYPTO_INFO_FILE_NAME = "CryptoInfo.crp";
    private final String CRYPTO_INFO_ROOT_NODE_NAME = "cryptoInfo";
    private final String CRYPTO_INFO_KEY_NODE_NAME = "cryptoKey";
    private final String CRYPTO_INFO_PASSWORD_NODE_NAME = "cryptoPassword";
    private final String CRYPTO_INFO_SEED_NODE_NAME = "cryptoSeed";
    private final String CRYPTO_INFO_FILE_ENCRYPTION_KEY = 
            "iQw5UFIGDumVqUc2C66qP95gHv6WhFKV";
    private final String CRYPTO_INFO_FILE_SEED = "597";
    
    private ICrypto crypto;
    
    public CryptoFileManager() {
        crypto = new CryptoAES();
    }
    
    public CryptoFileManager(ICrypto crypto) {
        this.crypto = crypto;
    }
    
    @Override
    public void createCryptoInfoFile(SecretKey key, String password, int seed) throws Exception {
        createCryptoInfoFile(getDefaultCryptoDirectoryPath() + 
                File.separator + CRYPTO_INFO_FILE_NAME, key, password, seed);
    }
    
    @Override
    public void createCryptoInfoFile(String filepath, SecretKey key, String password, int seed) throws Exception {
        
        if (key.getEncoded().length == 32) {
            createCryptoDirectory(filepath.substring(0, filepath.lastIndexOf(File.separator)));
        
            File cryptoInfoFile = new File(filepath);
        
            if (cryptoInfoFile.exists()) {
                removeCryptoInfoFile(filepath);
            }
                
            cryptoInfoFile.createNewFile();
            
            String keyToStore = crypto.bytesToBase64(key.getEncoded());
            String encryptedPassword = crypto.encrypt(password, key, seed);
            
            String cryptoInfoXml = 
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
                "<" + CRYPTO_INFO_ROOT_NODE_NAME + ">" +
                "<" + CRYPTO_INFO_KEY_NODE_NAME + ">" + 
                keyToStore + 
                "</" + CRYPTO_INFO_KEY_NODE_NAME + ">" +
                "<" + CRYPTO_INFO_PASSWORD_NODE_NAME + ">" + 
                encryptedPassword + 
                "</" + CRYPTO_INFO_PASSWORD_NODE_NAME + ">" +
                "<" + CRYPTO_INFO_SEED_NODE_NAME + ">" + 
                String.valueOf(seed) + 
                "</" + CRYPTO_INFO_SEED_NODE_NAME + ">" +
                "</" + CRYPTO_INFO_ROOT_NODE_NAME + ">";                
                      
            saveContentAsEncryptedFile(filepath, cryptoInfoXml);
        }
        else {
            throw new Exception("Given key was not a valid 256 bit key!");
        }
    }
    
    @Override
    public void removeCryptoInfoFile() throws IOException {
        removeCryptoInfoFile(getDefaultCryptoDirectoryPath() + 
                File.separator + CRYPTO_INFO_FILE_NAME);
    }
    
    @Override
    public void removeCryptoInfoFile(String filepath) throws IOException {
        
        File cryptoInfoFile = new File(filepath);
        
        if (cryptoInfoFile.exists()) {
                cryptoInfoFile.delete();
                cryptoInfoFile.deleteOnExit();
        }
        else {
            throw new IOException(filepath + " - the given path does not exist!");
        }
    }
    
    @Override
    public SecretKey getStoredEncryptionKey(String password) throws Exception {
        return getStoredEncryptionKey(getDefaultCryptoDirectoryPath() + 
                File.separator + CRYPTO_INFO_FILE_NAME, password);
    }
    
    @Override
    public SecretKey getStoredEncryptionKey(String filepath, String password) 
            throws Exception {
        
        Document cryptoInfoXml = getXMLDocumentFromEncryptedCryptoInfoFile(filepath);
        Node rootNode = cryptoInfoXml.getFirstChild();
        String storedKey = null;
        
        for(int x = 0; x < rootNode.getChildNodes().getLength(); x++) {
            Node childNode = rootNode.getChildNodes().item(x);
            if (childNode.getNodeName().equals(CRYPTO_INFO_KEY_NODE_NAME)) {
                storedKey = childNode.getTextContent();
            }          
        }
        
        if (storedKey == null) {
            throw new AuthenticationException("Problem retrieving Stored CryptoInfo!");
        }
        
        SecretKey cryptoKey = crypto.getEncryptionKeyFromBytes(crypto.base64ToBytes(storedKey));
        
        if (isCryptoPasswordCorrect(password, filepath)) {
            return cryptoKey;
        }        
        else {
            throw new AuthenticationException("The password given was incorrect!");
        }
    }
    
    @Override
    public int getStoredCryptoSeed(String password) throws Exception {
        return getStoredCryptoSeed(getDefaultCryptoDirectoryPath() + 
                File.separator + CRYPTO_INFO_FILE_NAME, password);
    }
    
    @Override
    public int getStoredCryptoSeed(String filepath, String password) 
            throws Exception {
        
        Document cryptoInfoXml = getXMLDocumentFromEncryptedCryptoInfoFile(filepath);
        Node rootNode = cryptoInfoXml.getFirstChild();
        String storedSeed = null;
        
        for(int x = 0; x < rootNode.getChildNodes().getLength(); x++) {
            Node childNode = rootNode.getChildNodes().item(x);
            if (childNode.getNodeName().equals(CRYPTO_INFO_SEED_NODE_NAME)) {
                storedSeed = childNode.getTextContent();
            }          
        }
        
        if (storedSeed == null) {
            throw new AuthenticationException("Problem retrieving Stored CryptoInfo!");
        }
        
        int seed = Integer.parseInt(storedSeed);
        
        if (isCryptoPasswordCorrect(password, filepath)) {
            return seed;
        }
        else
        {
            throw new AuthenticationException("The password given was incorrect!");
        }
    }
    
    @Override
    public void updateStoredCryptoPassword(String oldPassword, String newPassword)
            throws Exception {
        updateStoredCryptoPassword(getDefaultCryptoDirectoryPath() + 
                File.separator + CRYPTO_INFO_FILE_NAME, oldPassword, newPassword);
    }
    
    @Override
    public void updateStoredCryptoPassword(String filepath, String oldPassword, String newPassword)
            throws Exception {
        
        Document cryptoInfoXml = getXMLDocumentFromEncryptedCryptoInfoFile(filepath);
        Node rootNode = cryptoInfoXml.getFirstChild();        
        Node passwordNode = null;
        
        for(int x = 0; x < rootNode.getChildNodes().getLength(); x++) {
            Node childNode = rootNode.getChildNodes().item(x);
            if (childNode.getNodeName().equals(CRYPTO_INFO_PASSWORD_NODE_NAME)) {
                passwordNode = childNode;
            }          
        }
        
        if (passwordNode == null) {
            throw new AuthenticationException("Problem retrieving Stored CryptoInfo!");
        }
        
        if (isCryptoPasswordCorrect(oldPassword, filepath)) {
            // Set the new password
            SecretKey key = getStoredEncryptionKey(filepath, oldPassword);
            int seed = getStoredCryptoSeed(filepath, oldPassword);
            String encryptedNewPassword = crypto.encrypt(newPassword, key, seed);
            
            passwordNode.setTextContent(encryptedNewPassword);
            
            // Get a string representation of the XML Content
            TransformerFactory transfac = TransformerFactory.newInstance();
            Transformer trans = transfac.newTransformer();
            trans.setOutputProperty(OutputKeys.METHOD, "xml");

            StringWriter sw = new StringWriter();
            String cryptoInfoXmlString = "";
                    
            try {
                StreamResult result = new StreamResult(sw);
                DOMSource source = new DOMSource(cryptoInfoXml.getDocumentElement());

                trans.transform(source, result);
                cryptoInfoXmlString = sw.toString();  
            }
            finally {
                sw.close();
            }
            
            // Save the updates
            saveContentAsEncryptedFile(filepath, cryptoInfoXmlString);
        }        
        else {
            throw new AuthenticationException("The password given was incorrect!");
        }
    }
    
    @Override
    public boolean validateCryptoPassword(String password) throws Exception {
        return validateCryptoPassword(getDefaultCryptoDirectoryPath(), password);
    }

    @Override
    public boolean validateCryptoPassword(String filepath, String password) throws Exception {
        return isCryptoPasswordCorrect(password, filepath);
    }
    
    @Override
    public boolean doesCryptoInfoFileExist() {
        return doesCryptoInfoFileExist(getDefaultCryptoDirectoryPath());
    }
    
    @Override
    public boolean doesCryptoInfoFileExist(String filepath) {
        File cryptoInfoFile = new File(filepath);
        
        if (cryptoInfoFile.exists()) {
            return true;
        }
        else {
            return false;
        }
    }
    
    private boolean isCryptoPasswordCorrect(String password, String filepath) throws Exception {
    
        Document cryptoInfoXml = getXMLDocumentFromEncryptedCryptoInfoFile(filepath);
        Node rootNode = cryptoInfoXml.getFirstChild();
        
        String storedKey = null;
        String storedPassword = null;
        String storedSeed = null;
        
        for(int x = 0; x < rootNode.getChildNodes().getLength(); x++) {
            Node childNode = rootNode.getChildNodes().item(x);
            
            if (childNode.getNodeName().equals(CRYPTO_INFO_KEY_NODE_NAME)) {
                storedKey = childNode.getTextContent();
            }
            if (childNode.getNodeName().equals(CRYPTO_INFO_PASSWORD_NODE_NAME)) {
                storedPassword = childNode.getTextContent();
            }
            if (childNode.getNodeName().equals(CRYPTO_INFO_SEED_NODE_NAME)) {
                storedSeed = childNode.getTextContent();
            }            
        }
        
        if (storedKey == null || storedPassword == null || storedSeed == null) {
            throw new AuthenticationException("Problem retrieving Stored CryptoInfo!");
        }
        
        SecretKey cryptoKey = crypto.getEncryptionKeyFromBytes(crypto.base64ToBytes(storedKey));
        int seed = Integer.parseInt(storedSeed);
        String decryptedStoredPassword = crypto.decrypt(storedPassword, cryptoKey, seed);
        
        if (password.equals(decryptedStoredPassword)) {
            return true;
        }
        else {
            return false;
        }
    }   
    
    private Document getXMLDocumentFromEncryptedCryptoInfoFile(String filepath) 
            throws Exception {
        
        String encryptedXml = "";
        
        // Get the encrypted contents from the CryptoInfo file
        File file = new File(filepath);
        BufferedReader br = new BufferedReader(new FileReader(file));
        String line;
        while ((line = br.readLine()) != null) {
            encryptedXml += line;
        }
        
        // Get the encryption key and decrypt the file contents
        SecretKey cryptoInfoKey = getCryptoInfoFileEncryptionKey();
        String decryptedXml = crypto.decrypt(encryptedXml, cryptoInfoKey, 
                Integer.parseInt(CRYPTO_INFO_FILE_SEED));
        
        // Parse the file contents into XML, and return as an XML Document
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        DocumentBuilder builder = factory.newDocumentBuilder();

        return builder.parse(new InputSource(new StringReader(decryptedXml)));
    }
    
    private String getDefaultCryptoDirectoryPath() {
        return System.getProperty("user.dir") + File.separator + "security";
    }
    
    private void createCryptoDirectory(String directoryPath) {
        File cryptoDirectory = new File(directoryPath);
        
        if (!cryptoDirectory.exists()) {
            cryptoDirectory.mkdir();
        }
    }

    private SecretKey getCryptoInfoFileEncryptionKey() throws Exception {
        return crypto.getEncryptionKeyFromBytes(CRYPTO_INFO_FILE_ENCRYPTION_KEY.getBytes());
    }
    
    private void saveContentAsEncryptedFile(String filepath, String fileContent) throws Exception {
        
        SecretKey fileEncryptionKey = getCryptoInfoFileEncryptionKey();
        int fileEncryptionSeed = Integer.parseInt(CRYPTO_INFO_FILE_SEED);
        
        String encryptedXml = 
            crypto.encrypt(fileContent, fileEncryptionKey, fileEncryptionSeed);
                 
        FileOutputStream fileStream = new FileOutputStream(filepath);
        Writer outputStream = new OutputStreamWriter(fileStream, "utf-8");
        Writer writer = new BufferedWriter(outputStream);

        try {            
            writer.write(encryptedXml);
        } catch (IOException ex) {
        } finally {
            writer.close();
            outputStream.close();
            fileStream.close();
        }  
    }
}
