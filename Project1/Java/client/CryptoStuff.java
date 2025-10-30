import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;

import java.security.Key;
import java.security.KeyStore;
import java.security.MessageDigest;

import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

public class CryptoStuff {
    private static final int GCM_NONCE_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 128;

    public static byte[] encrypt(byte[] plaintext, Key key, Key HMacKey, CryptoConfig cfg) throws Exception {
        if (cfg.isAEAD()) {
            // AES/GCM or ChaCha20-Poly1305 - AEAD modes
            Cipher cipher = Cipher.getInstance(cfg.cipherMode);
            // System.out.println("[INFO] Encrypting with " + cipher);
            byte[] nonce = new byte[GCM_NONCE_LENGTH];
            new SecureRandom().nextBytes(nonce);

            if (cfg.isChaCha()) {
                IvParameterSpec iv = new IvParameterSpec(nonce);
                cipher.init(Cipher.ENCRYPT_MODE, key, iv);

            } else if (cfg.isGCM()) {
                GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, nonce);
                cipher.init(Cipher.ENCRYPT_MODE, key, spec);

            } else {
                throw new IllegalArgumentException("Unsupported AEAD mode: " + cfg.cipherMode);
            }

            byte[] ciphertext = cipher.doFinal(plaintext);

            byte[] result = new byte[nonce.length + ciphertext.length];
            System.arraycopy(nonce, 0, result, 0, nonce.length);
            System.arraycopy(ciphertext, 0, result, nonce.length, ciphertext.length);
            return result;

        } else {
            // AES/CBC + HMAC
            Cipher cipher = Cipher.getInstance(cfg.cipherMode);
            // System.out.println("[INFO] Encrypting with " + cipher);
            byte[] iv = new byte[cipher.getBlockSize()];
            new SecureRandom().nextBytes(iv);
            cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
            byte[] ciphertext = cipher.doFinal(plaintext);

            // Add HMAC for integrity if defined
            if (!cfg.hmacAlgo.equalsIgnoreCase("NONE")) {
                Mac mac = Mac.getInstance(cfg.hmacAlgo);
                mac.init(HMacKey);
                mac.update(iv);
                mac.update(ciphertext);
                byte[] tag = mac.doFinal();

                ByteArrayOutputStream out = new ByteArrayOutputStream();
                out.write(iv);
                out.write(ciphertext);
                out.write(tag);
                return out.toByteArray();

            } else {
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                out.write(iv);
                out.write(ciphertext);
                return out.toByteArray();
            }
        }
    }

    public static byte[] decrypt(byte[] data, Key key, Key HMacKey, CryptoConfig cfg) throws Exception {
        if (cfg.isAEAD()) {
            // AES/GCM or ChaCha20-Poly1305
            Cipher cipher = Cipher.getInstance(cfg.cipherMode);
            byte[] nonce = Arrays.copyOfRange(data, 0, 12);
            byte[] ciphertext = Arrays.copyOfRange(data, 12, data.length);

            if (cfg.isChaCha()) {
                IvParameterSpec iv = new IvParameterSpec(nonce);
                cipher.init(Cipher.DECRYPT_MODE, key, iv);

            } else if (cfg.isGCM()) {
                GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, nonce);
                cipher.init(Cipher.DECRYPT_MODE, key, spec);

            } else {
                throw new IllegalArgumentException("Unsupported AEAD mode: " + cfg.cipherMode);
            }

            return cipher.doFinal(ciphertext);

        } else {

            Cipher cipher = Cipher.getInstance(cfg.cipherMode);
            int blockSize = cipher.getBlockSize();
            int tagLen = cfg.hmacAlgo.equalsIgnoreCase("NONE") ? 0 : Mac.getInstance(cfg.hmacAlgo).getMacLength();

            byte[] iv = Arrays.copyOfRange(data, 0, blockSize);
            byte[] ciphertext, tag;

            if (!cfg.hmacAlgo.equalsIgnoreCase("NONE")) {

                ciphertext = Arrays.copyOfRange(data, blockSize, data.length - tagLen);
                tag = Arrays.copyOfRange(data, data.length - tagLen, data.length);
                Mac mac = Mac.getInstance(cfg.hmacAlgo);
                mac.init(HMacKey);
                mac.update(iv);
                mac.update(ciphertext);
                byte[] expectedTag = mac.doFinal();
                if (!MessageDigest.isEqual(tag, expectedTag)) {
                    throw new SecurityException("HMAC verification failed!");
                }
            } else {
                ciphertext = Arrays.copyOfRange(data, blockSize, data.length);
            }

            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
            return cipher.doFinal(ciphertext);
        }
    }

    public static KeyStore createKeyStore(String fileName, String pw) throws Exception {
        File file = new File(fileName);

        final KeyStore keyStore = KeyStore.getInstance("JCEKS");
        if (file.exists()) {
            // keystore already exists -> load it
            keyStore.load(new FileInputStream(file), pw.toCharArray());
        } else {
            // keystore not created yet -> create it
            keyStore.load(null, null);
            keyStore.store(new FileOutputStream(fileName), pw.toCharArray());
        }

        return keyStore;
    }

    public static SecretKey loadOrGenerateKey(KeyStore keyStore, String alias, String ksPassword, CryptoConfig cfg)
            throws Exception {
        // Try to retrieve the AES key from keystore
        if (keyStore.containsAlias(alias)) {
            KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(ksPassword.toCharArray());
            KeyStore.SecretKeyEntry entry = (KeyStore.SecretKeyEntry) keyStore.getEntry(alias, protParam);
            return entry.getSecretKey();
        }

        String algorithm;
        if (cfg.cipherMode.toUpperCase().contains("CHACHA20")) {
            algorithm = "ChaCha20";
        } else {
            algorithm = "AES";
        }

        // Otherwise, generate and store a new one
        KeyGenerator keyGen = KeyGenerator.getInstance(algorithm);
        keyGen.init(cfg.keySize);
        SecretKey newKey = keyGen.generateKey();

        KeyStore.SecretKeyEntry skEntry = new KeyStore.SecretKeyEntry(newKey);
        KeyStore.PasswordProtection protParam = new KeyStore.PasswordProtection(ksPassword.toCharArray());
        keyStore.setEntry(alias, skEntry, protParam);

        // Save keystore back to disk
        try (FileOutputStream fos = new FileOutputStream("clientkeystore.jceks")) {
            keyStore.store(fos, ksPassword.toCharArray());
        }
        System.out.println("[INFO] New key generated and stored in keystore.");
        return newKey;
    }

    public static SecretKey loadOrGenerateHMACKey(KeyStore keyStore, String alias, String ksPassword, CryptoConfig cfg)
            throws Exception {

        if (cfg.isAEAD() || cfg.hmacAlgo.equalsIgnoreCase("NONE")) {
            return null;
        }

        if (keyStore.containsAlias(alias)) {
            KeyStore.ProtectionParameter prot = new KeyStore.PasswordProtection(ksPassword.toCharArray());
            KeyStore.SecretKeyEntry entry = (KeyStore.SecretKeyEntry) keyStore.getEntry(alias, prot);
            return entry.getSecretKey();
        }

        int macKeySize = cfg.macKeySize;
        byte[] keyBytes = new byte[macKeySize / 8];
        new SecureRandom().nextBytes(keyBytes);
        SecretKey newKey = new SecretKeySpec(keyBytes, cfg.hmacAlgo);

        KeyStore.SecretKeyEntry skEntry = new KeyStore.SecretKeyEntry(newKey);
        KeyStore.PasswordProtection prot = new KeyStore.PasswordProtection(ksPassword.toCharArray());
        keyStore.setEntry(alias, skEntry, prot);

        try (FileOutputStream fos = new FileOutputStream("clientkeystore.jceks")) {
            keyStore.store(fos, ksPassword.toCharArray());
        }

        System.out.println("[INFO] New HMAC key generated and stored in keystore.");
        return newKey;
    }

    public static String generateKeywordToken(Key keywordKey, String keyword) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(keywordKey);
        byte[] tag = mac.doFinal(keyword.trim().toLowerCase().getBytes(StandardCharsets.UTF_8));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(tag);
    }

    public static SecretKey loadOrGenerateKeywordKey(KeyStore keyStore, String alias, String ksPassword)
            throws Exception {
        if (keyStore.containsAlias(alias)) {
            KeyStore.ProtectionParameter prot = new KeyStore.PasswordProtection(ksPassword.toCharArray());
            KeyStore.SecretKeyEntry entry = (KeyStore.SecretKeyEntry) keyStore.getEntry(alias, prot);
            return entry.getSecretKey();
        }

        // Always use HMAC-SHA256 for keyword tokens
        byte[] keyBytes = new byte[32]; // 256 bits
        new SecureRandom().nextBytes(keyBytes);
        SecretKey newKey = new SecretKeySpec(keyBytes, "HmacSHA256");

        KeyStore.SecretKeyEntry skEntry = new KeyStore.SecretKeyEntry(newKey);
        KeyStore.PasswordProtection prot = new KeyStore.PasswordProtection(ksPassword.toCharArray());
        keyStore.setEntry(alias, skEntry, prot);

        try (FileOutputStream fos = new FileOutputStream("clientkeystore.jceks")) {
            keyStore.store(fos, ksPassword.toCharArray());
        }

        System.out.println("[INFO] New keyword HMAC key generated and stored in keystore.");
        return newKey;
    }

}
