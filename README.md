# TP 03: L’AES

## Objectif :

Créer un programme qui permet de crypter et de décrypter un fichier en utilisant l’Algo AES.

## Enoncé

- Commencer par créer un message de type string à crypter

```java
    String message = "Hello World";
```

- Sauvegarder le message à transmettre dans un fichier (message.txt)

```java
    try (FileOutputStream fos = new FileOutputStream("message.txt")) {
        fos.write(message.getBytes());
    } catch (Exception e) {
        e.printStackTrace();
    }
```

- Crypter le message en utilisant l’AES :

  - La clé doit être sauvegardée dans un fichier (cle.key)
  - Ecrire une fonction qui permet la génération et la sauvegarde de la clé

  ```java
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
  ```

  - Ecrire une fonction pour le cryptage et une autre pour le décryptage

  ```java
  public static String encrypt(String algorithm, String input, SecretKey key)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {

        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] cipherText = cipher.doFinal(input.getBytes());
        try (FileOutputStream fos = new FileOutputStream("message_encrypted.txt")) {
            fos.write(cipherText);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return Base64.getEncoder().encodeToString(cipherText);
    }
  ```

  - Décrypter le cryptogramme pour avoir le message en clair en utilisant le fichier `cryptogramme.txt`

  ```java
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
  ```

- Tester le programme

```java
public static void main(String[] args) throws Exception {
    SecretKey key = generateKey(128);
    String message = "Hello World";
    try (FileOutputStream fos = new FileOutputStream("message.txt")) {
        fos.write(message.getBytes());
    } catch (Exception e) {
        e.printStackTrace();
    }
    String cypherText = encrypt("AES", message, key);
    System.out.println(cypherText);
    String plainText = decrypt("AES", "message_encrypted.txt", key);
    System.out.println(plainText);
}
```

