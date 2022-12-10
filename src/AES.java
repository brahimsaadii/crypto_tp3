import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public class App {

    // generation de la clé
    public static SecretKey generateKey(int n) throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(n);
        SecretKey key = keyGenerator.generateKey();
        try (FileOutputStream fos = new FileOutputStream("cle.key")) {
            fos.write(key.getEncoded());
        } catch (Exception e) {
            e.printStackTrace();
        }
        return key;
    }

    // methode pour le cryptage
    public static String encrypt(String algorithm, String input, SecretKey key)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {

        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] cipherText = cipher.doFinal(input.getBytes());
        try (FileOutputStream fos = new FileOutputStream("message_crypter.txt")) {
            fos.write(cipherText);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return Base64.getEncoder().encodeToString(cipherText);
    }

    // methode pour le decryptage
    public static String decrypt(String algorithm, String file, SecretKey key)
            throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {
        byte[] cipherText = null;
        try (FileInputStream fis = new FileInputStream(file)) {
            cipherText = new byte[fis.available()];
            fis.read(cipherText);
        } catch (Exception e) {
            e.printStackTrace();
        }
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] plainText = cipher.doFinal(cipherText);
        return new String(plainText);

    }

    public static void main(String[] args) throws Exception {
        SecretKey key = generateKey(128);
        String message = "TP 03 crypto";
        try (FileOutputStream fos = new FileOutputStream("message_en_claire.txt")) {
            fos.write(message.getBytes());
        } catch (Exception e) {
            e.printStackTrace();
        }

        // get the message from text file

        String fileName = "message_en_claire.txt";
        Path path = Paths.get(fileName);
        List<String> message_list = Files.readAllLines(path, StandardCharsets.UTF_8);
        String message_en_claire = String.join(", ", message_list);

        // cryptage et decryptage du message
        String message_crypter = encrypt("AES", message_en_claire, key);
        System.out.println("le message crypter est : " + message_crypter);
        String message_claire = decrypt("AES", "message_crypter.txt", key);
        System.out.println("le message en claire est : " + message_claire);
    }

}
