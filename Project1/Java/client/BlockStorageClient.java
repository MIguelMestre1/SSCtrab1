
import java.io.*;
import java.net.*;
import java.security.Key;
import java.security.MessageDigest;
import java.util.*;

import javax.crypto.SecretKey;
import java.security.KeyStore;

public class BlockStorageClient {
    private static final int PORT = 5000;
    private static final int BLOCK_SIZE = 4096;
    private static final String INDEX_FILE = "client_index.ser";
    private static final String CLIENT_KEY_STORE = "clientkeystore.jceks";

    private static Map<String, List<String>> fileIndex = new HashMap<>();

    public static void main(String[] args) throws IOException, ClassNotFoundException, Exception {
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

        // Load the CryptoConfig file
        CryptoConfig cfg = CryptoConfig.load("cryptoconfig.txt");
        System.out.println("[INFO] Loaded crypto config: " + cfg.cipherMode);

        // Load or generate the AES key
        SecretKey key = CryptoStuff.loadOrGenerateKey(clKeyStore, "clientKey", keystorePassword, cfg);

        // Load or generate HMAC key
        SecretKey HMacKey = CryptoStuff.loadOrGenerateHMACKey(clKeyStore, "clientHMACKey", keystorePassword, cfg);

        // Load or generate HMAC key to generate tokens
        SecretKey keywordKey = CryptoStuff.loadOrGenerateKeywordKey(clKeyStore, "keywordKey", keystorePassword);

        Socket socket = new Socket("localhost", PORT);
        try (
                DataInputStream in = new DataInputStream(socket.getInputStream());
                DataOutputStream out = new DataOutputStream(socket.getOutputStream());
                Scanner scanner = new Scanner(System.in);) {
            while (true) {
                System.out.print("Command (PUT/GET/LIST/SEARCH/EXIT): ");
                String cmd = scanner.nextLine().toUpperCase();

                switch (cmd) {
                    case "PUT":
                        System.out.print("Enter local file path: ");
                        String path = scanner.nextLine();
                        File file = new File(path);
                        if (!file.exists()) {
                            System.out.println("File does not exist.");
                            continue;
                        }
                        System.out.print("Enter keywords (comma-separated): ");
                        String kwLine = scanner.nextLine();
                        List<String> keywords = new ArrayList<>();
                        if (!kwLine.trim().isEmpty()) {
                            for (String kw : kwLine.split(","))
                                keywords.add(kw.trim().toLowerCase());
                        }

                        putFile(file, keywords, out, in, key, HMacKey, keywordKey, cfg);
                        saveIndex();
                        break;

                    case "GET":
                        System.out.print("Enter filename to retrieve: ");
                        String filename = scanner.nextLine();
                        getFile(filename, out, in, key, HMacKey, cfg);
                        break;

                    case "LIST":
                        out.writeUTF("LIST_BLOCKS");
                        out.flush();

                        int numBlocks = in.readInt();
                        if (numBlocks == 0) {
                            System.out.println("\n[INFO] No files stored on the server.");
                            break;
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
                        break;

                    case "SEARCH":
                        System.out.print("Enter keyword to search: ");
                        String keyword = scanner.nextLine();
                        searchFiles(keyword, out, in, keywordKey);
                        break;

                    case "EXIT":
                        out.writeUTF("EXIT");
                        out.flush();
                        saveIndex();
                        return;

                    default:
                        System.out.println("Unknown command.");
                        break;
                }
            }
        } finally {
            socket.close();
        }
    }

    private static void putFile(File file, List<String> keywords,
            DataOutputStream out, DataInputStream in, Key key, Key HMacKey, Key keywordKey, CryptoConfig cfg)
            throws Exception {
        List<String> blocks = new ArrayList<>();
        try (FileInputStream fis = new FileInputStream(file)) {
            byte[] buffer = new byte[BLOCK_SIZE];
            int bytesRead;
            int blockNum = 0;
            while ((bytesRead = fis.read(buffer)) != -1) {
                byte[] plainBlock = Arrays.copyOf(buffer, bytesRead);
                byte[] encryptedBlock = CryptoStuff.encrypt(plainBlock, key, HMacKey, cfg);

                String blockId = Base64.getUrlEncoder().encodeToString(
                        MessageDigest.getInstance("SHA-256").digest(encryptedBlock));

                out.writeUTF("STORE_BLOCK");
                out.writeUTF(blockId);
                out.writeInt(encryptedBlock.length);
                out.write(encryptedBlock);

                // Keywords only on the first block
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
                System.out.print("."); // for debug
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

    private static void getFile(String filename,
            DataOutputStream out, DataInputStream in, Key key, Key HMacKey, CryptoConfig cfg) throws Exception {
        List<String> blocks = fileIndex.get(filename);
        if (blocks == null) {
            System.out.println("File not found.");
            return;
        }

        File clientDir = new File("clientfiles");
        if (!clientDir.exists())
            clientDir.mkdirs();

        File outFile = new File(clientDir, filename);
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
        } else {
            System.out.println("\n[WARN] Integrity check failed. File not deleted from server.");
        }
    }

    private static void searchFiles(String keyword, DataOutputStream out,
            DataInputStream in, Key HMacKey) throws Exception {

        // generate token for keyword
        String token = CryptoStuff.generateKeywordToken(HMacKey, keyword);

        out.writeUTF("SEARCH");
        out.writeUTF(token);
        out.flush();

        int count = in.readInt();
        System.out.println();
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
