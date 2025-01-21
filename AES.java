import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.File;
import java.io.FileInputStream;
import java.security.*;
import java.util.Base64;

/*
Generate an AES key using one class, and encrypt it with a public key. Using the same AES
key, encrypt a random XML string and sign it with the public key.
*/
public class AES {

    private static SecretKey key;
    private PrivateKey privateKey;
    private PublicKey publicKey;
    private byte[] encryptedKeyBytes;
    private byte[] encryptedXmlBytes;
    private byte[] xmlData;
    private byte[] iv;
    private byte[] digitalSignature;

    public SecretKey getKey(){
        return key;
    }

    public byte[] getDigitalSignature(){
        return digitalSignature;
    }
    // Add getter for IV
    public byte[] getIV() {
        return iv;
    }

    public PrivateKey getPrivateKey() {
        return privateKey; // Ensure `privateKey` is a class-level variable in AES
    }

    public PublicKey getPublicKey(){
        return publicKey;
    }
    public byte[] getXmlData(){
        return xmlData;
    }
    public byte[] getEncryptedKeyBytes() {
        return encryptedKeyBytes; // Provide a way to access it
    }

    public byte[] getEncryptedXmlBytes(){
        return encryptedXmlBytes;
    }

    public static KeyPair generateRsaKeyPair() throws Exception{

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        // Define the size of the key
        keyPairGenerator.initialize(1024);
        return keyPairGenerator.generateKeyPair();
    }

    public static byte[] encrypt(SecretKey key, PublicKey publicKey) throws Exception{

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(key.getEncoded());
    }

    public static byte[] readXmlData(File xmlFile) throws Exception{
        FileInputStream fis = new FileInputStream(xmlFile);
        byte[] xmlData = new byte[ (int) xmlFile.length()];
        fis.read(xmlData);
        fis.close();
        return xmlData;
    }

    private static String encode(byte[] data){
        return Base64.getEncoder().encodeToString(data);
    }

    private static byte[] signString(byte[] xml, PrivateKey privateKey) throws Exception{
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(xml);
        return signature.sign();
    }

    public void implementation() throws Exception{

        // Generate AES secretKey

        KeyGenerator generator = null;
        generator = KeyGenerator.getInstance("AES");
        generator.init(128);
        this.key = generator.generateKey();

        // Generate a rsa key pair


        KeyPair keyPair = generateRsaKeyPair();
        this.publicKey = keyPair.getPublic();
        this.privateKey = keyPair.getPrivate();

        // Encrypt the AES key with the RSA public key

        this.encryptedKeyBytes = encrypt(key, publicKey);

        // Convert the encrypted key to a String using Base64 encoding

        String encryptedKey = Base64.getEncoder().encodeToString(encryptedKeyBytes);
        System.out.println("Encrypted AES Key: " + encryptedKey);

        // Reading the xml file

        File xmlFile = new File("sample.xml");
        this.xmlData = readXmlData(xmlFile);

        // Using the same AES key, encrypt a random XML string

        Cipher encryptionCipher = Cipher.getInstance("AES/GCM/NoPadding");
        encryptionCipher.init(Cipher.ENCRYPT_MODE, key);
        this.iv = encryptionCipher.getIV();  // Store the IV
        this.encryptedXmlBytes = encryptionCipher.doFinal(xmlData);
        String EncryptedXmlAes = encode(encryptedXmlBytes);

        // and sign it with the private key
        this.digitalSignature = signString(EncryptedXmlAes.getBytes(), privateKey);
    }

}
