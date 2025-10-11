
import java.io.*;
import java.net.*;
import java.security.MessageDigest;
import java.util.*;

import javax.crypto.SecretKey;

public class BlockStorageClient {
    private static final int PORT = 5000;
    private static final int BLOCK_SIZE = 4096;
    private static final String INDEX_FILE = "client_index.ser";
    private static final String KEY_FILE = "clientkey.bin";

    private static Map<String, List<String>> fileIndex = new HashMap<>();

    public static void main(String[] args) throws IOException, ClassNotFoundException, Exception {
        loadIndex();

        SecretKey key;
        File keyFile = new File(KEY_FILE);
        if (keyFile.exists()) {
            key = CryptoStuff.loadKey(KEY_FILE);
            System.out.println("Existing AES key loaded.");
        } else {
            key = CryptoStuff.generateKey();
            CryptoStuff.saveKey(key, KEY_FILE);
            System.out.println("New AES key generated and saved to " + KEY_FILE);
        }

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
                        putFile(file, keywords, out, in, key);
                        saveIndex();
                        break;

                    case "GET":
                        System.out.print("Enter filename to retrieve: ");
                        String filename = scanner.nextLine();
                        getFile(filename, out, in, key);
                        break;

                    case "LIST":
                        System.out.println("Stored files:");
                        for (String f : fileIndex.keySet())
                            System.out.println(" - " + f);
                        break;

                    case "SEARCH":
                        System.out.print("Enter keyword to search: ");
                        String keyword = scanner.nextLine();
                        searchFiles(keyword, out, in);
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
            DataOutputStream out, DataInputStream in, SecretKey key) throws Exception {
        List<String> blocks = new ArrayList<>();
        try (FileInputStream fis = new FileInputStream(file)) {
            byte[] buffer = new byte[BLOCK_SIZE];
            int bytesRead;
            int blockNum = 0;
            while ((bytesRead = fis.read(buffer)) != -1) {
                byte[] plainBlock = Arrays.copyOf(buffer, bytesRead);
                byte[] encryptedBlock = CryptoStuff.encrypt(plainBlock, key);

                // Block ID (opaco)
                String blockId = Base64.getUrlEncoder().encodeToString(
                        MessageDigest.getInstance("SHA-256").digest(encryptedBlock));

                out.writeUTF("STORE_BLOCK");
                out.writeUTF(blockId);
                out.writeInt(encryptedBlock.length);
                out.write(encryptedBlock);

                // Keywords apenas no primeiro bloco
                if (blockNum == 0) {
                    out.writeInt(keywords.size());
                    for (String kw : keywords)
                        out.writeUTF(kw);
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
                System.out.print("."); // progress indicator
            }
        }
        fileIndex.put(file.getName(), blocks);
        System.out.println("\n File stored securely with " + blocks.size() + " encrypted blocks.");
    }

    private static void getFile(String filename,
            DataOutputStream out, DataInputStream in, SecretKey key) throws Exception {
        List<String> blocks = fileIndex.get(filename);
        if (blocks == null) {
            System.out.println("File not found in local index.");
            return;
        }
        try (FileOutputStream fos = new FileOutputStream("retrieved_" + filename)) {
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

                // Decifrar e verificar integridade (GCM)
                byte[] decrypted = CryptoStuff.decrypt(encrypted, key);
                fos.write(decrypted);
                System.out.print(".");
            }
        }
        System.out.println();
        System.out.println("File reconstructed: retrieved_" + filename);
    }

    private static void searchFiles(String keyword, DataOutputStream out, DataInputStream in) throws IOException {
        out.writeUTF("SEARCH");
        out.writeUTF(keyword.toLowerCase());
        out.flush();
        int count = in.readInt();
        System.out.println();
        System.out.println("Search results:");
        for (int i = 0; i < count; i++) {
            System.out.println(" - " + in.readUTF());
        }
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
