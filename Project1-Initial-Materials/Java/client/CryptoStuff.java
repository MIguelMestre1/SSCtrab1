import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;

import java.security.Key;
import java.security.KeyStore;

import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.SecureRandom;
import java.util.Base64;

public class CryptoStuff {
    private static final int AES_KEY_SIZE = 256;
    private static final int GCM_NONCE_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 128;

    // Cifra um bloco de bytes e devolve nonce+ciphertext+tag
    public static byte[] encrypt(byte[] plaintext, Key key) throws Exception {
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
    public static byte[] decrypt(byte[] encrypted, Key key) throws Exception {
        byte[] nonce = new byte[GCM_NONCE_LENGTH];
        System.arraycopy(encrypted, 0, nonce, 0, nonce.length);
        byte[] ciphertext = new byte[encrypted.length - nonce.length];
        System.arraycopy(encrypted, nonce.length, ciphertext, 0, ciphertext.length);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, nonce);
        cipher.init(Cipher.DECRYPT_MODE, key, spec);

        return cipher.doFinal(ciphertext);
    }

    public static KeyStore createKeyStore(String fileName, String pw) throws Exception {
        File file = new File(fileName);

        final KeyStore keyStore = KeyStore.getInstance("JCEKS");
        if (file.exists()) {
            // .keystore file already exists => load it
            keyStore.load(new FileInputStream(file), pw.toCharArray());
        } else {
            // .keystore file not created yet => create it
            keyStore.load(null, null);
            keyStore.store(new FileOutputStream(fileName), pw.toCharArray());
        }

        return keyStore;
    }

    public static SecretKey loadOrGenerateAESKey(KeyStore keyStore, String alias, String ksPassword)
            throws Exception {
        // Try to retrieve the AES key from keystore
        if (keyStore.containsAlias(alias)) {
            KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(ksPassword.toCharArray());
            KeyStore.SecretKeyEntry entry = (KeyStore.SecretKeyEntry) keyStore.getEntry(alias, protParam);
            System.out.println("[INFO] Loaded AES key from keystore.");
            return entry.getSecretKey();
        }

        // Otherwise, generate and store a new one
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey newKey = keyGen.generateKey();

        KeyStore.SecretKeyEntry skEntry = new KeyStore.SecretKeyEntry(newKey);
        KeyStore.PasswordProtection protParam = new KeyStore.PasswordProtection(ksPassword.toCharArray());
        keyStore.setEntry(alias, skEntry, protParam);

        // Save keystore back to disk
        try (FileOutputStream fos = new FileOutputStream("clientkeystore.jceks")) {
            keyStore.store(fos, ksPassword.toCharArray());
        }
        System.out.println("[INFO] New AES key generated and stored in keystore.");
        return newKey;
    }

    public static SecretKey loadOrGenerateHMACKey(KeyStore keyStore, String alias, String ksPassword)
            throws Exception {
        if (keyStore.containsAlias(alias)) {
            KeyStore.ProtectionParameter prot = new KeyStore.PasswordProtection(ksPassword.toCharArray());
            KeyStore.SecretKeyEntry entry = (KeyStore.SecretKeyEntry) keyStore.getEntry(alias, prot);
            System.out.println("[INFO] Loaded HMAC key from keystore.");
            return entry.getSecretKey();
        }

        byte[] keyBytes = new byte[32];
        new SecureRandom().nextBytes(keyBytes);
        SecretKey newKey = new SecretKeySpec(keyBytes, "HmacSHA256");

        KeyStore.SecretKeyEntry skEntry = new KeyStore.SecretKeyEntry(newKey);
        KeyStore.PasswordProtection prot = new KeyStore.PasswordProtection(ksPassword.toCharArray());
        keyStore.setEntry(alias, skEntry, prot);

        try (FileOutputStream fos = new FileOutputStream("clientkeystore.jceks")) {
            keyStore.store(fos, ksPassword.toCharArray());
        }

        System.out.println("[INFO] New HMAC key generated and stored in keystore.");
        return newKey;
    }

    // Gera o token determinístico para uma keyword
    public static String generateKeywordToken(Key keywordKey, String keyword) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(keywordKey);
        byte[] tag = mac.doFinal(keyword.trim().toLowerCase().getBytes(StandardCharsets.UTF_8));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(tag);
    }
}

// Gera e devolve uma nova chave AES-256
// public static Key generateKey() throws Exception {
// KeyGenerator keyGen = KeyGenerator.getInstance("AES");
// keyGen.init(AES_KEY_SIZE);
// return keyGen.generateKey();
// }

// // Guarda a chave num ficheiro Base64
// public static void saveKey(Key key, String path) throws Exception {
// String encoded = Base64.getEncoder().encodeToString(key.getEncoded());
// java.nio.file.Files.write(java.nio.file.Paths.get(path), encoded.getBytes());
// }

// // Lê a chave de um ficheiro Base64
// public static Key loadKey(String path) throws Exception {
// byte[] data =
// java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(path));
// byte[] decoded = Base64.getDecoder().decode(new String(data));
// return new javax.crypto.spec.SecretKeySpec(decoded, "AES");
// }

// public static Key loadOrGenerateKeywordKey(String path) throws Exception {
// File f = new File(path);
// if (f.exists()) {
// byte[] encoded = Files.readAllBytes(f.toPath());
// byte[] raw = Base64.getDecoder().decode(new String(encoded).trim());
// return new SecretKeySpec(raw, "HmacSHA256");
// } else {
// byte[] key = new byte[32]; // 256 bits
// new SecureRandom().nextBytes(key);
// Key secret = new SecretKeySpec(key, "HmacSHA256");
// Files.write(f.toPath(), Base64.getEncoder().encode(secret.getEncoded()));
// return secret;
// }
// }