import java.io.*;
import java.net.*;
import java.security.*;
import java.util.*;

import javax.crypto.SecretKey;

public class cltest {
    private static final int PORT = 5000;
    private static final String INDEX_FILE = "client_index.ser";
    private static final String KEY_FILE = "clientkey.bin";
    private static final String CLIENT_KEY_STORE = "clientkeystore.jceks";
    private static final int BLOCK_SIZE = 4096;

    private static Map<String, List<String>> fileIndex = new HashMap<>();

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.out.println("Usage:");
            System.out.println("  cltest PUT <path/file> <keywords>");
            System.out.println("  cltest LIST");
            System.out.println("  cltest SEARCH <keywords>");
            System.out.println("  cltest GET <file> <path>");
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

        // Load or generate the AES key inside the keystore
        SecretKey key = CryptoStuff.loadOrGenerateAESKey(clKeyStore, "clientAESKey", keystorePassword);

        // Load or generate keyword HMAC key
        SecretKey metaKey = CryptoStuff.loadOrGenerateHMACKey(clKeyStore, "keywordHMACKey", keystorePassword);

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
                List<String> keywords = Arrays.asList(args[2].split(","));
                putFile(file, keywords, out, in, key, metaKey);
                saveIndex();
                break;

            case "LIST":
                listFiles(out, in);
                break;

            case "SEARCH":
                if (args.length < 2) {
                    System.out.println("Usage: cltest SEARCH <keywords>");
                    return;
                }
                searchFiles(args[1], out, in, metaKey);
                break;

            case "GET":
                if (args.length >= 3 && args[1].equals("CHECKINTEGRITY")) {
                    checkIntegrity(args[2], out, in, key);
                } else if (args.length == 3) {
                    getFile(args[1], args[2], out, in, key);
                } else {
                    System.out.println("Usage: cltest GET <file> <path>");
                    return;
                }
                break;

            default:
                System.out.println("Unknown command: " + command);
                break;
        }

        socket.close();
    }

    // ==== PUT ====
    private static void putFile(File file, List<String> keywords, DataOutputStream out,
            DataInputStream in, Key key, Key metaKey) throws Exception {
        List<String> blocks = new ArrayList<>();
        try (FileInputStream fis = new FileInputStream(file)) {
            byte[] buffer = new byte[BLOCK_SIZE];
            int bytesRead, blockNum = 0;
            while ((bytesRead = fis.read(buffer)) != -1) {
                byte[] plainBlock = Arrays.copyOf(buffer, bytesRead);
                byte[] encryptedBlock = CryptoStuff.encrypt(plainBlock, key);

                String blockId = Base64.getUrlEncoder().encodeToString(
                        MessageDigest.getInstance("SHA-256").digest(encryptedBlock));

                out.writeUTF("STORE_BLOCK");
                out.writeUTF(blockId);
                out.writeInt(encryptedBlock.length);
                out.write(encryptedBlock);

                if (blockNum == 0) {
                    out.writeInt(keywords.size());
                    for (String kw : keywords) {
                        String token = CryptoStuff.generateKeywordToken(metaKey, kw);
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
        System.out.println("\n File stored securely with " + blocks.size() + " blocks.");

        if (file.delete()) {
            System.out.println("[INFO] Original file deleted from client after upload: " + file.getName());
        } else {
            System.out.println("[WARN] Could not delete local file: " + file.getAbsolutePath());
        }
    }

    // ==== GET ====
    private static void getFile(String filename, String outDir, DataOutputStream out,
            DataInputStream in, Key key) throws Exception {
        List<String> blocks = fileIndex.get(filename);
        if (blocks == null) {
            System.out.println("File not found in local index.");
            return;
        }
        File clientDir = new File("clientfiles");
        if (!clientDir.exists())
            clientDir.mkdirs();

        File outFile = new File(clientDir, filename);
        try (FileOutputStream fos = new FileOutputStream(outFile)) {
            for (String blockId : blocks) {
                out.writeUTF("GET_BLOCK");
                out.writeUTF(blockId);
                out.flush();
                int length = in.readInt();
                if (length == -1) {
                    System.out.println("Block not found: " + blockId);
                    return;
                }
                byte[] encrypted = new byte[length];
                in.readFully(encrypted);

                try {
                    byte[] decrypted = CryptoStuff.decrypt(encrypted, key);
                    fos.write(decrypted);
                    System.out.print(".");
                } catch (javax.crypto.AEADBadTagException e) {
                    System.out.println("\n✖ Integrity FAILED for block " + blockId);
                    fos.close();
                    outFile.delete();
                    return;
                }
            }
        }
        System.out.println();
        System.out.println("File reconstructed at: clientfiles");
    }

    // ==== CHECK INTEGRITY ====
    private static void checkIntegrity(String path, DataOutputStream out, DataInputStream in, Key key)
            throws Exception {
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
                System.out.println("✖ Missing block: " + blockId);
                allOk = false;
                continue;
            }

            byte[] encrypted = new byte[length];
            in.readFully(encrypted);

            try {
                CryptoStuff.decrypt(encrypted, key);
                System.out.println("Block OK: " + blockId);
            } catch (javax.crypto.AEADBadTagException e) {
                System.out.println("Integrity FAILED for block: " + blockId);
                allOk = false;
            }
        }

        System.out.println(allOk ? "\n All blocks verified successfully." : "\n Integrity check failed.");
    }

    // ==== SEARCH ====
    private static void searchFiles(String keyword, DataOutputStream out, DataInputStream in, Key metaKey)
            throws IOException, Exception {

        String token = CryptoStuff.generateKeywordToken(metaKey, keyword);

        out.writeUTF("SEARCH");
        out.writeUTF(token);
        out.flush();

        int count = in.readInt();
        System.out.println("\nSearch results:");
        for (int i = 0; i < count; i++)
            System.out.println(" - " + in.readUTF());
    }

    // ==== LIST ====
    private static void listFiles(DataOutputStream out, DataInputStream in) throws IOException {
        out.writeUTF("LIST_BLOCKS");
        out.flush();

        int numBlocks = in.readInt();
        if (numBlocks == 0) {
            System.out.println("\n[INFO] No files stored on the server.");
            return;
        }

        System.out.println("\n[INFO] Files stored on the server:");
        for (int i = 0; i < numBlocks; i++) {
            String blockName = in.readUTF();
            System.out.println(" - " + blockName);
        }
    }

    // ==== INDEX ====
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
