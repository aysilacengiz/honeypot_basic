#print("honeypot_ssh.pyy")

#libraries
from asyncio import Server
import logging
from logging.handlers import RotatingFileHandler   
import socket 
import paramiko
import threading


#constants
logging_format = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
SSH_BANNER = "SSH-2.0-OpenSSH_7.4" #META DATA ABOUT THE SSH SERVER

#host_key = 'server.key'
host_key = paramiko.RSAKey(filename='server.key') #RSA key for the SSH server


#loggers & logging files
funnel_logger = logging.getLogger("funnel_logger")
funnel_logger.setLevel(logging.INFO)
funnel_handler = RotatingFileHandler("audits.log", maxBytes=1000000, backupCount=5)
funnel_handler.setFormatter(logging_format)
funnel_logger.addHandler(funnel_handler)

creds_logger = logging.getLogger("creds_logger")
creds_logger.setLevel(logging.INFO)
creds_handler = RotatingFileHandler("cmd_audits.log", maxBytes=1000000, backupCount=5)
creds_handler.setFormatter(logging_format)
creds_logger.addHandler(creds_handler)


#Emulated SHELL : the commands hackers will try to run on the honeypot will be logged in the audits.log file.
def emulated_shell(channel, client_ip):
    channel.send(b"corporate-vault ")
    command = b" "
    while True:
        char = channel.recv(1024)
        channel.send(char)
        if not char:
            channel.close()
        
        command += char
        
        if char == b"\r":
            if command.strip() == b" exit":
                response = b" Bye!\r\n"
                channel.close()
            elif command.strip() == b"help":
                response = b"Available commands: help, exit, whoami, ls, pwd\r\n"
                creds_logger.info(f"Command {command.strip()} executed by : {client_ip}")
            elif command.strip() == b"pwd":
                response = b"/home/user\r\n" + b"\r\n"
                creds_logger.info(f"Command {command.strip()} executed by : {client_ip}")
            elif command.strip() == b"whoami":
                response = b"user\r\n" + b"\r\n"
                creds_logger.info(f"Command {command.strip()} executed by : {client_ip}")
            elif command.strip() == b"ls":
                response = b" file1.txt \r\nfile2.txt \r\nfile3.txt \r\n" + b" \r\n"
                creds_logger.info(f"Command {command.strip()} executed by : {client_ip}")           
            elif command.strip() == b"cat file1.txt":
                response = b" This is a sample file.\r\n" + b"\r\n"
                creds_logger.info(f"Command {command.strip()} executed by : {client_ip}")
            else:
                response = b"\n" + bytes(f"Command not found: {command.strip().decode()}\r\n", 'utf-8') + b"\r\n"
            
            channel.send(response)
            channel.send(b"corporate-vault ")
            command = b" "

#SSH SERVER + SOCKETS

class SSHServer(paramiko.ServerInterface):

    def __init__(self, client_ip, input_username = None, input_password = None):
        self.event= threading.Event() #creating an event object to handle the channel requests
        self.client_ip = client_ip
        self.input_username = input_username
        self.input_password = input_password

    def check_channel_request(self, kind: str, chanid: int)->int:
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def get_allowed_auths(self,username):
        return "password"

    def check_auth_password(self,username, password):
         #logging the credentials to the creds_logger for auditing purposes
        funnel_logger.info(f"Client {self.client_ip} attempted to login with username: {username} and password: {password}")
        creds_logger.info(f"{self.client_ip},{username},{password}")

       


        if self.input_username is not None and self.input_password is not None:
            if username == self.input_username and password == self.input_password:
                #creds_logger.info("Successful login attempt from %s with username: %s and password: %s", self.client_ip, username, password)
                return paramiko.AUTH_SUCCESSFUL
            else: 
                return paramiko.AUTH_FAILED
        else: 
            return paramiko.AUTH_SUCCESSFUL

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True 

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_exec_request(self,channel,command):
        command = str(command, 'utf-8')
        return True


def client_handle(client,address,username,password):
    client_ip = address[0]
    print(f"{client_ip} has connected to the SSHv2")


    try:
        transport = paramiko.Transport(client)
        transport.local_version = SSH_BANNER #CUSTOM AND CONSTANT
        server = SSHServer(client_ip=client_ip, input_username=username, input_password=password)
        transport.add_server_key(host_key)
        transport.start_server(server= server)

        channel = transport.accept(100)
        if channel is None:
            print("No channel was opened. Closing connection.")

        standart_banner = "Welcome to the SSH honeypot. All activities are logged.\n"
        channel.send(standart_banner)
        emulated_shell(channel,client_ip = client_ip)

    except Exception as error:
        print(error)
        print("!!!Error!!!")
    finally:
        try:
            transport.close()
        except Exception as error:
            print(error)
        client.close()




#PROVİSİON ssh-ased honeypot

def honeypot(address,port,username,password):

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((address,port))

    server_socket.listen(100) #100 is the maximum number of queued connections
    print(f"[*] Listening for connection on {address}:{port}...")

    #build out logic that will handle incoming connections and spawn a new thread for each connection
    while True:
        try:
            client, addr = server_socket.accept()
            #threadding because we want to handle multiple connections at the same time
            honeypot_thread = threading.Thread(target=client_handle, args=(client,addr,username,password))
            honeypot_thread.start()
        except Exception as error:
            print(error)
            print("!!!Error!!!")


honeypot('0.0.0.0', 2223 , 'admin', '121212') #honwypot works uı can be upgraded

      