#### Install requirements:
    pip install -r requirements.txt


# run server:
    python server.py <server name>

<server name>: 
    The server name parameter is used to start the server using the parameters in server.json, 
    including the public and private keys of the server, and the port on which it runs.

    In this project, the private keys of all servers are saved in the same file. 
    This is a wrong practice and is only for demonstration. 
    In a production environment, environment variables should be used and private keys should not be shared.


# run client:
    python client.py <server name>

<server name>:
    This parameter specifies the server the user connects to. 
    The server configuration is found in server.json.

    Note that in actual applications, server.json does not contain the server's private key, only the public key. 
    This file is only used for demonstration purposes.



## Usage
The client is interactive and will prompt you to do the following operation:
"
    1. send public message
    2. send private message
    3. show client list
    4. upload file
    5. download file
    0. exit
"


The downloaded files will be stored in the downloads/ directory, 
and the files uploaded to the server will be stored in the uploads/ directory.