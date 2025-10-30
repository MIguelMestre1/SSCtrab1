import java.io.*;
import java.net.*;
import java.security.*;
import java.util.*;
import javax.crypto.SecretKey;

public class cltest {
    private static final int PORT = 5000;
    private static final String INDEX_FILE = "client_index.ser";
    private static final String CLIENT_KEY_STORE = "clientkeystore.jceks";
    private static final int BLOCK_SIZE = 4096;

    private static Map<String, List<String>> fileIndex = new HashMap<>();

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.out.println("Usage:");
            System.out.println("  cltest PUT <path/file> <keywords>");
            System.out.println("  cltest LIST");
            System.out.println("  cltest SEARCH <keyword>");
            System.out.println("  cltest GET <filename>");
            System.out.println("  cltest GET <keyword>");
            System.out.println("  cltest GET CHECKINTEGRITY <path/file>");
            return;
        }

        loadIndex();

        Scanner inputScanner = new Scanner(System.in);
        KeyStore clKeyStore = null;
        String keystorePassword = null;

        while (true) {
            System.out.print("Enter keystore password: ");
            keystorePassword = inputScanner.nextLine();
            try {
                clKeyStore = CryptoStuff.createKeyStore(CLIENT_KEY_STORE, keystorePassword);
                break;
            } catch (IOException e) {
                System.out.println("[ERROR] Incorrect password or corrupted keystore. Please try again.");
            }
        }

        // Load crypto configuration
        CryptoConfig cfg = CryptoConfig.load("cryptoconfig.txt");
        // System.out.println("[INFO] Loaded crypto config: " + cfg.cipherMode);

        // Load or generate AES key
        SecretKey key = CryptoStuff.loadOrGenerateKey(clKeyStore, "clientKey", keystorePassword, cfg);

        // Load or generate HMAC key
        SecretKey HMacKey = CryptoStuff.loadOrGenerateHMACKey(clKeyStore, "clientHMACKey", keystorePassword, cfg);

        // Load or generate HMAC key to generate tokens
        SecretKey keywordKey = CryptoStuff.loadOrGenerateKeywordKey(clKeyStore, "keywordKey", keystorePassword);

        Socket socket = new Socket("localhost", PORT);
        DataInputStream in = new DataInputStream(socket.getInputStream());
        DataOutputStream out = new DataOutputStream(socket.getOutputStream());

        String command = args[0].toUpperCase();

        switch (command) {
            case "PUT":
                if (args.length < 3) {
                    System.out.println("Usage: cltest PUT <path/file> <keywords>");
                    return;
                }
                File file = new File(args[1]);
                if (!file.exists()) {
                    System.out.println("File not found: " + args[1]);
                    return;
                }
                List<String> keywords = new ArrayList<>();
                for (String kw : args[2].split(",")) {
                    keywords.add(kw.trim().toLowerCase());
                }
                putFile(file, keywords, out, in, key, HMacKey, keywordKey, cfg);
                saveIndex();
                break;

            case "GET":
                if (args.length == 3 && args[1].equalsIgnoreCase("CHECKINTEGRITY")) {
                    checkIntegrity(args[2], out, in, key, HMacKey, cfg);
                } else if (args.length >= 2) {
                    String arg = args[1];
                    String targetDir = args.length >= 3 ? args[2] : "clientfiles"; // default

                    // Check if argument is a known filename
                    if (fileIndex.containsKey(arg)) {
                        getFile(arg, targetDir, out, in, key, HMacKey, cfg);
                    } else {
                        // Assume keyword mode
                        getFileByKeyword(arg, targetDir, out, in, key, HMacKey, keywordKey, cfg);
                    }
                } else {
                    System.out.println("Usage:");
                    System.out.println("  cltest GET <filename> <path/dir>");
                    System.out.println("  cltest GET <keyword> <path/dir>");
                    System.out.println("  cltest GET CHECKINTEGRITY <path/file>");
                }
                break;

            case "LIST":
                listFiles(out, in);
                break;

            case "SEARCH":
                if (args.length < 2) {
                    System.out.println("Usage: cltest SEARCH <keyword>");
                    return;
                }
                searchFiles(args[1], out, in, HMacKey, keywordKey);
                break;

            default:
                System.out.println("Unknown command: " + command);
                break;
        }

        socket.close();
    }

    private static void putFile(File file, List<String> keywords,
            DataOutputStream out, DataInputStream in,
            Key key, Key HMacKey, Key keywordKey, CryptoConfig cfg) throws Exception {
        List<String> blocks = new ArrayList<>();
        try (FileInputStream fis = new FileInputStream(file)) {
            byte[] buffer = new byte[BLOCK_SIZE];
            int bytesRead, blockNum = 0;
            while ((bytesRead = fis.read(buffer)) != -1) {
                byte[] plainBlock = Arrays.copyOf(buffer, bytesRead);
                byte[] encryptedBlock = CryptoStuff.encrypt(plainBlock, key, HMacKey, cfg);

                String blockId = Base64.getUrlEncoder().encodeToString(
                        MessageDigest.getInstance("SHA-256").digest(encryptedBlock));

                out.writeUTF("STORE_BLOCK");
                out.writeUTF(blockId);
                out.writeInt(encryptedBlock.length);
                out.write(encryptedBlock);

                if (blockNum == 0) {
                    out.writeInt(keywords.size());
                    for (String kw : keywords) {
                        String token = CryptoStuff.generateKeywordToken(keywordKey, kw);
                        out.writeUTF(token);
                    }
                } else {
                    out.writeInt(0);
                }

                out.flush();
                String response = in.readUTF();
                if (!response.equals("OK")) {
                    System.out.println("Error storing block: " + blockId);
                    return;
                }

                blocks.add(blockId);
                blockNum++;
                System.out.print(".");
            }
        }
        fileIndex.put(file.getName(), blocks);
        System.out.println("\n File stored securely with " + blocks.size() + " encrypted blocks.");

        if (file.delete()) {
            System.out.println("[INFO] Original file deleted from client after upload: " + file.getName());
        } else {
            System.out.println("[WARN] Could not delete local file: " + file.getAbsolutePath());
        }
    }

    private static void getFile(String filename, String targetDir,
            DataOutputStream out, DataInputStream in,
            Key key, Key HMacKey, CryptoConfig cfg) throws Exception {

        List<String> blocks = fileIndex.get(filename);
        if (blocks == null) {
            System.out.println("File not found.");
            return;
        }

        File outputDir = new File(targetDir);
        if (!outputDir.exists())
            outputDir.mkdirs();

        File outFile = new File(outputDir, filename);
        boolean allOk = true;

        try (FileOutputStream fos = new FileOutputStream(outFile)) {
            for (String blockId : blocks) {
                out.writeUTF("GET_BLOCK");
                out.writeUTF(blockId);
                out.flush();

                int length = in.readInt();
                if (length == -1) {
                    System.out.println("Missing block: " + blockId);
                    allOk = false;
                    continue;
                }

                byte[] encrypted = new byte[length];
                in.readFully(encrypted);

                try {
                    byte[] decrypted = CryptoStuff.decrypt(encrypted, key, HMacKey, cfg);
                    fos.write(decrypted);
                    System.out.print(".");
                } catch (javax.crypto.AEADBadTagException e) {
                    System.out.println("\nIntegrity FAILED for block: " + blockId);
                    allOk = false;
                    break;
                }
            }
        }

        if (allOk) {
            out.writeUTF("DELETE_BLOCKS");
            out.writeInt(blocks.size());
            for (String blockId : blocks) {
                out.writeUTF(blockId);
            }
            out.flush();

            String response = in.readUTF();
            System.out.println("\n[SERVER] " + response);
            System.out.println("[INFO] File saved at: " + outFile.getAbsolutePath());
        } else {
            System.out.println("\n[WARN] Integrity check failed. File not deleted from server.");
        }
    }

    private static void getFileByKeyword(String keyword, String targetDir,
            DataOutputStream out, DataInputStream in,
            Key key, Key HMacKey, Key keywordKey, CryptoConfig cfg) throws Exception {

        System.out.println("[INFO] Searching for files with keyword: " + keyword);

        String token = CryptoStuff.generateKeywordToken(keywordKey, keyword);

        out.writeUTF("SEARCH");
        out.writeUTF(token);
        out.flush();

        int count = in.readInt();
        if (count == 0) {
            System.out.println("[INFO] No files found for keyword: " + keyword);
            return;
        }

        System.out.println("[INFO] Found " + count + " block(s) for keyword '" + keyword + "'");

        List<String> blockIds = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            blockIds.add(in.readUTF());
        }

        Set<String> matchedFiles = new HashSet<>();
        for (String blockId : blockIds) {
            String filename = findFileByBlock(blockId);
            if (filename != null)
                matchedFiles.add(filename);
        }

        if (matchedFiles.isEmpty()) {
            System.out.println("[WARN] Keyword found on server, but no local index mapping for the files.");
            return;
        }

        File outputDir = new File(targetDir);
        if (!outputDir.exists())
            outputDir.mkdirs();

        System.out.println("[INFO] Downloading all files containing keyword: " + keyword);
        for (String fileName : matchedFiles) {
            System.out.println(" - Downloading file: " + fileName);
            getFile(fileName, targetDir, out, in, key, HMacKey, cfg);
        }

        System.out.println("[INFO] All matching files downloaded to: " + outputDir.getAbsolutePath());
    }

    private static void checkIntegrity(String path, DataOutputStream out, DataInputStream in,
            Key key, Key HMacKey, CryptoConfig cfg) throws Exception {
        File f = new File(path);
        String filename = f.getName();
        List<String> blocks = fileIndex.get(filename);
        if (blocks == null) {
            System.out.println("File not found in local index.");
            return;
        }

        System.out.println("[INFO] Checking integrity of " + filename + "...");
        boolean allOk = true;
        for (String blockId : blocks) {
            out.writeUTF("GET_BLOCK");
            out.writeUTF(blockId);
            out.flush();

            int length = in.readInt();
            if (length == -1) {
                System.out.println("Missing block: " + blockId);
                allOk = false;
                continue;
            }

            byte[] encrypted = new byte[length];
            in.readFully(encrypted);

            try {
                CryptoStuff.decrypt(encrypted, key, HMacKey, cfg);
                System.out.println("Block OK: " + blockId);
            } catch (javax.crypto.AEADBadTagException e) {
                System.out.println("Integrity FAILED for block: " + blockId);
                allOk = false;
            }
        }

        System.out.println(allOk ? "\nAll blocks verified successfully." : "\nIntegrity check failed.");
    }

    private static void listFiles(DataOutputStream out, DataInputStream in) throws IOException {
        out.writeUTF("LIST_BLOCKS");
        out.flush();

        int numBlocks = in.readInt();
        if (numBlocks == 0) {
            System.out.println("\n[INFO] No files stored on the server.");
            return;
        }

        System.out.println("\n[INFO] Files stored on the server:");
        Set<String> printedFiles = new HashSet<>();
        for (int i = 0; i < numBlocks; i++) {
            String blockId = in.readUTF();
            String fileName = findFileByBlock(blockId);
            if (fileName != null && !printedFiles.contains(fileName)) {
                System.out.println(" - " + fileName);
                printedFiles.add(fileName);
            }
        }
    }

    private static void searchFiles(String keyword, DataOutputStream out,
            DataInputStream in, Key HMacKey, Key keywordKey) throws Exception {
        String token = CryptoStuff.generateKeywordToken(keywordKey, keyword);

        out.writeUTF("SEARCH");
        out.writeUTF(token);
        out.flush();

        int count = in.readInt();
        if (count != 0) {
            System.out.println("Search results:");
            for (int i = 0; i < count; i++) {
                String blockId = in.readUTF();
                String fileName = findFileByBlock(blockId);
                if (fileName != null)
                    System.out.println(" - " + fileName + " (block: " + blockId + ")");
                else
                    System.out.println(" - block: " + blockId);
            }
        } else {
            System.out.println("There is no file with keyword " + keyword + " stored in the server");
        }
    }

    private static String findFileByBlock(String blockId) {
        for (Map.Entry<String, List<String>> entry : fileIndex.entrySet()) {
            if (entry.getValue().contains(blockId))
                return entry.getKey();
        }
        return null;
    }

    private static void saveIndex() {
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(INDEX_FILE))) {
            oos.writeObject(fileIndex);
        } catch (IOException e) {
            System.err.println("Failed to save index: " + e.getMessage());
        }
    }

    private static void loadIndex() {
        File f = new File(INDEX_FILE);
        if (!f.exists())
            return;
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(f))) {
            fileIndex = (Map<String, List<String>>) ois.readObject();
        } catch (IOException | ClassNotFoundException e) {
            System.err.println("Failed to load index: " + e.getMessage());
        }
    }
}
