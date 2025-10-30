README – How to Test the Secure Block Storage System

1. Start the server

   - Run the BlockStorageServer program.
   - It will start listening on port 5000 and create the folder “blockstorage” to store encrypted blocks.

2. Open another terminal and run the client

   - When running for the first time, it will ask to set the password for future use
   - It will also create the keystore and generate clientKey, clientHMACKey and keywordKey

3. To upload a file to the server

   - Command: cltest PUT <path/file> <keywords>
   - Example: cltest PUT clientfiles/find.txt project,report
   - The file will be encrypted, split into blocks, and stored on the server.
   - The original file is deleted from the client after upload.

4. To list all files currently stored on the server

   - Command: cltest LIST
   - Displays the names of all files stored on the server.

5. To search for files by keyword

   - Command: cltest SEARCH <keyword>
   - Example: cltest SEARCH project
   - Shows all files that were stored with that keyword.

6. To retrieve a specific file by name

   - Command: cltest GET <filename> <output_directory>
   - Example: cltest GET document.txt clientfiles
   - The file will be downloaded, decrypted, verified for integrity, and saved in the specified directory.
   - If integrity is confirmed, the corresponding blocks are deleted from the server.

7. To retrieve files by keyword

   - Command: cltest GET <keyword> <output_directory>
   - Example: cltest GET project clientfiles
   - All files matching that keyword will be automatically downloaded and saved in the specified directory.

8. To check file integrity without downloading

   - Command: cltest GET CHECKINTEGRITY <path/file>
   - This verifies that all blocks of the file are still valid on the server.

9. To exit the client
   - Command: EXIT
   - The connection will close, and the local index is saved automatically.
