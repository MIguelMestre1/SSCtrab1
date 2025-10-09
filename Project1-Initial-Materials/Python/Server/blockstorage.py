
import os
import socket
import threading
import pickle

SERVER_HOST = '0.0.0.0'
SERVER_PORT = 5500
BLOCK_SIZE = 1024  # 1KB Blocks in this case
STORAGE_DIR = 'blockstorage'
METADATA_FILE = 'metadata.pkl'

os.makedirs(STORAGE_DIR, exist_ok=True)

# Load or initialize metadata
if os.path.exists(METADATA_FILE):
    with open(METADATA_FILE, 'rb') as f:
        metadata = pickle.load(f)
else:
    metadata = {}  # filename -> {'blocks': [...], 'keywords': [...]}


def save_metadata():
    with open(METADATA_FILE, 'wb') as f:
        pickle.dump(metadata, f)


def handle_client(client_socket):
    try:
        while True:
            command = client_socket.recv(1024).decode()
            if not command:
                break
            cmd_parts = command.strip().split()
            if len(cmd_parts) == 0:
                continue

            action = cmd_parts[0].upper()

            if action == 'PUT':
                filename = cmd_parts[1]
                keywords = cmd_parts[2:] if len(cmd_parts) > 2 else []

                # Receive file size
                filesize = int(client_socket.recv(1024).decode())
                client_socket.send(b'ACK')  # ack to start sending file

                blocks = []
                remaining = filesize
                block_index = 0
                while remaining > 0:
                    chunk_size = min(BLOCK_SIZE, remaining)
                    block_data = b''
                    while len(block_data) < chunk_size:
                        data = client_socket.recv(chunk_size - len(block_data))
                        if not data:
                            break
                        block_data += data
                    block_name = f"{filename}_block{block_index}"
                    with open(os.path.join(STORAGE_DIR, block_name), 'wb') as bf:
                        bf.write(block_data)
                    blocks.append(block_name)
                    remaining -= len(block_data)
                    block_index += 1

                metadata[filename] = {'blocks': blocks, 'keywords': keywords}
                save_metadata()
                client_socket.send(f"File {filename} stored successfully.".encode())

            elif action == 'GET':
                filename = cmd_parts[1]
                if filename not in metadata:
                    client_socket.send(b"ERROR: File not found")
                    continue

                blocks = metadata[filename]['blocks']
                filesize = sum(os.path.getsize(os.path.join(STORAGE_DIR, b)) for b in blocks)
                client_socket.send(str(filesize).encode())
                client_socket.recv(1024)  # wait for ack

                for block in blocks:
                    with open(os.path.join(STORAGE_DIR, block), 'rb') as bf:
                        data = bf.read()
                        client_socket.sendall(data)

            elif action == 'LIST':
                files = '\n'.join(metadata.keys())
                client_socket.send(files.encode())

            elif action == 'SEARCH':
                keyword = cmd_parts[1]
                results = [fname for fname, data in metadata.items() if keyword in data['keywords']]
                client_socket.send('\n'.join(results).encode())

            else:
                client_socket.send(b"ERROR: Unknown command")

    except Exception as e:
        print(f"Client error: {e}")
    finally:
        client_socket.close()


def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((SERVER_HOST, SERVER_PORT))
    server.listen(5)
    print(f"[*] Server listening on {SERVER_HOST}:{SERVER_PORT}")

    while True:
        client_socket, addr = server.accept()
        print(f"[*] Accepted connection from {addr}")
        threading.Thread(target=handle_client, args=(client_socket,)).start()


if __name__ == "__main__":
    main()
