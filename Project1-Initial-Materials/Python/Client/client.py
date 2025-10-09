
import socket
import os

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 5500
BLOCK_SIZE = 1024  # 1KB blocks


def put_file(sock):
    filepath = input("Enter path of file to upload: ")
    if not os.path.exists(filepath):
        print("File does not exist.")
        return

    filename = os.path.basename(filepath)
    keywords = input("Enter keywords for search (space separated): ").split()

    # Send PUT command
    sock.send(f"PUT {filename} {' '.join(keywords)}".encode())

    # Send file size
    filesize = os.path.getsize(filepath)
    sock.send(str(filesize).encode())

    # Wait for ACK
    sock.recv(1024)

    # Send file in blocks
    with open(filepath, 'rb') as f:
        while True:
            bytes_read = f.read(BLOCK_SIZE)
            if not bytes_read:
                break
            sock.sendall(bytes_read)

    print(sock.recv(1024).decode())


def get_file(sock):
    filename = input("Enter filename to download: ")
    sock.send(f"GET {filename}".encode())
    response = sock.recv(1024).decode()
    if response.startswith("ERROR"):
        print(response)
        return

    filesize = int(response)
    sock.send(b'ACK')
    remaining = filesize

    with open(f"downloaded_{filename}", 'wb') as f:
        while remaining > 0:
            data = sock.recv(min(BLOCK_SIZE, remaining))
            if not data:
                break
            f.write(data)
            remaining -= len(data)

    print(f"File {filename} downloaded successfully as downloaded_{filename}")


def list_files(sock):
    sock.send(b"LIST")
    files = sock.recv(4096).decode()
    print("Files on server:")
    print(files if files else "(No files)")


def search_files(sock):
    keyword = input("Enter keyword to search: ")
    sock.send(f"SEARCH {keyword}".encode())
    results = sock.recv(4096).decode()
    print("Search results:")
    print(results if results else "(No files found)")


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((SERVER_HOST, SERVER_PORT))
    print("Connected to server.")

    while True:
        print("\nMenu:")
        print("1. Upload file (PUT)")
        print("2. Download file (GET)")
        print("3. List files")
        print("4. Search files")
        print("5. Exit")
        choice = input("Enter choice: ")

        if choice == '1':
            put_file(sock)
        elif choice == '2':
            get_file(sock)
        elif choice == '3':
            list_files(sock)
        elif choice == '4':
            search_files(sock)
        elif choice == '5':
            break
        else:
            print("Invalid choice.")

    sock.close()


if __name__ == "__main__":
    main()
