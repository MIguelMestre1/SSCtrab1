import java.io.*;
import java.util.*;

public class CryptoConfig {
    public String cipherMode;
    public int keySize;
    public String hmacAlgo;
    public int macKeySize;

    public static CryptoConfig load(String path) throws IOException {
        Properties props = new Properties();
        try (FileInputStream fis = new FileInputStream(path)) {
            props.load(fis);
        }

        CryptoConfig cfg = new CryptoConfig();
        cfg.cipherMode = props.getProperty("CIPHER", "AES/GCM/NoPadding").trim();
        cfg.keySize = Integer.parseInt(props.getProperty("KEYSIZE", "256"));
        cfg.hmacAlgo = props.getProperty("HMAC", "NONE").trim();
        cfg.macKeySize = Integer.parseInt(props.getProperty("MACKEYSIZE", "0"));
        return cfg;
    }

    public boolean isAEAD() {
        return cipherMode.toUpperCase().contains("GCM") || cipherMode.toUpperCase().contains("CHACHA20");
    }

}
