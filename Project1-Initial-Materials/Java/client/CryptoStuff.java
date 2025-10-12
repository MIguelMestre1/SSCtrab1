import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.SecureRandom;
import java.util.Base64;

public class CryptoStuff {
    private static final int AES_KEY_SIZE = 256;
    private static final int GCM_NONCE_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 128;

    // Gera e devolve uma nova chave AES-256
    public static SecretKey generateKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(AES_KEY_SIZE);
        return keyGen.generateKey();
    }

    // Cifra um bloco de bytes e devolve nonce+ciphertext+tag
    public static byte[] encrypt(byte[] plaintext, SecretKey key) throws Exception {
        byte[] nonce = new byte[GCM_NONCE_LENGTH];
        new SecureRandom().nextBytes(nonce);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, nonce);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);

        byte[] ciphertext = cipher.doFinal(plaintext);

        byte[] result = new byte[nonce.length + ciphertext.length];
        System.arraycopy(nonce, 0, result, 0, nonce.length);
        System.arraycopy(ciphertext, 0, result, nonce.length, ciphertext.length);
        return result;
    }

    // Decifra um bloco a partir de nonce+ciphertext+tag
    public static byte[] decrypt(byte[] encrypted, SecretKey key) throws Exception {
        byte[] nonce = new byte[GCM_NONCE_LENGTH];
        System.arraycopy(encrypted, 0, nonce, 0, nonce.length);
        byte[] ciphertext = new byte[encrypted.length - nonce.length];
        System.arraycopy(encrypted, nonce.length, ciphertext, 0, ciphertext.length);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, nonce);
        cipher.init(Cipher.DECRYPT_MODE, key, spec);

        return cipher.doFinal(ciphertext);
    }

    // Guarda a chave num ficheiro Base64
    public static void saveKey(SecretKey key, String path) throws Exception {
        String encoded = Base64.getEncoder().encodeToString(key.getEncoded());
        java.nio.file.Files.write(java.nio.file.Paths.get(path), encoded.getBytes());
    }

    // Lê a chave de um ficheiro Base64
    public static SecretKey loadKey(String path) throws Exception {
        byte[] data = java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(path));
        byte[] decoded = Base64.getDecoder().decode(new String(data));
        return new javax.crypto.spec.SecretKeySpec(decoded, "AES");
    }

    public static SecretKey loadOrGenerateKeywordKey(String path) throws Exception {
        File f = new File(path);
        if (f.exists()) {
            byte[] encoded = Files.readAllBytes(f.toPath());
            byte[] raw = Base64.getDecoder().decode(new String(encoded).trim());
            return new SecretKeySpec(raw, "HmacSHA256");
        } else {
            byte[] key = new byte[32]; // 256 bits
            new SecureRandom().nextBytes(key);
            SecretKey secret = new SecretKeySpec(key, "HmacSHA256");
            Files.write(f.toPath(), Base64.getEncoder().encode(secret.getEncoded()));
            return secret;
        }
    }

    // Gera o token determinístico para uma keyword
    public static String generateKeywordToken(SecretKey keywordKey, String keyword) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(keywordKey);
        byte[] tag = mac.doFinal(keyword.trim().toLowerCase().getBytes(StandardCharsets.UTF_8));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(tag);
    }
}
