import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.util.Base64;



/*
In another class, decrypt the encrypted AES Key using the private key. Using this AES key,
decrypt the encrypted XML string and check if it has been tampered with by using the
private key.
 */

public class Main {

    private byte[] IV;
    // Add setter for IV
    public void setIV(byte[] iv) {
        this.IV = iv;
    }

    public static String decryption(byte [] aesKey, PrivateKey privateKey) throws Exception{
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte [] decryptedOriginalArray = cipher.doFinal(aesKey);
        return new String(decryptedOriginalArray);
    }

    private byte[] decode(String data){
        return Base64.getDecoder().decode(data);
    }

    public String decrypt(String encryptedMesssage) throws Exception{
        AES aes = new AES();
        byte[] messageInBytes = decode(encryptedMesssage);
        Cipher decryptionCipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, IV);
        decryptionCipher.init(Cipher.DECRYPT_MODE, aes.getKey(), spec);
        byte[] decryptedBytes = decryptionCipher.doFinal(messageInBytes);
        return new String(decryptedBytes);
    }

    public static boolean verifySignature(byte[] string, byte[] digitalSignature, PublicKey publicKey) throws Exception{
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(publicKey);
        signature.update(string);
        return signature.verify(digitalSignature);

    }

    public static void main(String[] args) throws Exception {


        AES aes = new AES();
        aes.implementation();

        // Retrieve the private key from AES and encrypted key
        PrivateKey privateKey = aes.getPrivateKey();
        byte[] encryptedKeyBytes = aes.getEncryptedKeyBytes();

        // Decryption of AES secretKey
        String originalMessage = decryption(encryptedKeyBytes, privateKey);
        String stringOriginal = new String(originalMessage);
        System.out.println("The decrypted key from cipher is : " + stringOriginal);

        Main main = new Main();
        main.setIV(aes.getIV());  // Set the IV before decryption

        // Decrypt XML file
        byte[] encryptedXmlBytes = aes.getEncryptedXmlBytes();
        String encryptedXmlString = Base64.getEncoder().encodeToString(encryptedXmlBytes);
        String decryptedXml = main.decrypt(encryptedXmlString);
        System.out.println("Decrypted XML: " + decryptedXml);

        // Check if file has been tampered with
        boolean verified = verifySignature(encryptedXmlString.getBytes(), aes.getDigitalSignature(), aes.getPublicKey());
        if(verified) System.out.println("The signature is verified.");
        else System.out.println("The signature is not verified!!");
    }
}