import security.SecurityExample;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class Main {
    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        SecretKey secretKey = SecurityExample.generateKey(128);
        String message = "Hello, World!";
        IvParameterSpec iv = SecurityExample.generateIv();
        String algorithm = "AES/CBC/PKCS5Padding";
        String cipherMessage = SecurityExample.encrypt(algorithm, message, secretKey, iv);
        String decryptedMessage = SecurityExample.decrypt(algorithm, cipherMessage, secretKey, iv);
        System.out.println("Original Message: " + message);
        System.out.println("Encrypted Message: " + cipherMessage);
        System.out.println("Decrypted Message: " + decryptedMessage);
    }
}