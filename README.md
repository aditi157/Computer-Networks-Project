# Computer-Networks-Project
An FTP server is created used FileZilla (the server only allows local connections). 
enc.py is used to encrypt a text file by entering the path of the file when prompted. The encrypted files are stored in \encrypted (which will be created if it does not already exist), and the randomly generated key is stored in a database file (which will also be created if it does not exist). After this, the file is to be uploaded to the directory which is shared in the FTP server. (NOTE: none of the above is to be done by the user/client. They should access the server and the files through app.py)

The user/client can access the server and the files, as well as decrypt the encrypted files through app.py. The user will be prompted to register/login. After this, they will be directed to a page where they can access the ftp server, or decrypt an encrypted file.
On attempting to access the server, the user will be asked for a username and password for the server. On entering these, the user can download the encrypted files from the server. 
To decrypt the file, enter the name of the file (without the .enc extention), the key and the path of the folder in which the file is located. The decrypted file can then be downloaded. Note that the user must have the key in order to decrypt the file. 
(Python packages required for app.py: Flask, Flask-SQLAlchemy, Werkzeug, Cryptography)
