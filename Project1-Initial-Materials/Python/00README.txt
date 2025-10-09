
This is a python 3 implementation for a client server application.
The provided solution implments a persistent blockstorage service
(implemented by th server).

The server supports the following client requests supportd by
TCP (using TCP sockets for the commnication between the client and
the server)

* put: put files in the server persistent block storage
system with the fles sent in blocks to be maintained in th server

* list: lists stored files stored in blocks in the server

* get blocks for reconstruction of files from the server stored blocks

* search files stored on remote blocks using keywords stored in a
  metadata file indexing the searchable keywords.

The provided code implements a working client-server implementation
in Python 3 that handles the above operatons for clients:
PUT, GET, LIST, and SEARCH 


Server Functionality

The server stores files in blocks persistently,
maintains metadata for keyword search,
and supports PUT, GET, LIST, and SEARCH commands.


Client Functionality:

PUT / GET: Works for large files, stored in blocks.
LIST: Lists all files on server.
SEARCH: Finds files by keywords.
Uses a persistent metadata: Stored in metadata.pkl.

The client provides a command-line menu to
interact with the server and select files to send or to get and reconstruct
the retrieved blocks in the local filesystem.

Noe that th client mus maintai an index to know the blocks related each
file sent to be stored (in blocks) in the server persistet block storage

