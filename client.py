from tools import *
import websockets
import asyncio
import json
import hashlib
import base64
from typing import List
import aioconsole
import aiohttp
import os

debug_log = True



class Client:
    def __init__(self, ws_url:str) -> None:
        # generate rsa keys
        self.pem_public_key, self.pem_private_key = generate_rsa_keys()
        # self.__load_test_key()
        self.ws_url = ws_url
        self.http_url = ws_url.replace('ws://', 'http://')
        self.websocket:websockets.WebSocketClientProtocol = None
        self.msg_counter:int = 0
        self.clients:dict = None
        
        self.server_msg_counter = -1
        self.server_public_key:str = None
        return
    
    # def __load_test_key(self):
    #     # print(json.dumps({
    #     #     'public': self.pem_public_key.decode('utf-8'),
    #     #     'private': self.pem_private_key.decode('utf-8')
    #     # }))
    #     with open('test_key.txt', 'r') as f:
    #         data = json.load(f)
    #         self.pem_public_key, self.pem_private_key = data['public'].encode('utf-8'), data['private'].encode('utf-8')
    #     return
    
    async def send_client_hello(self):
        await self.__send_data(data={
            'type': 'hello',
            'public_key': self.pem_public_key.decode()
        })
        return
    
    
    async def send_private_msg(self):
        
        if self.clients is None:
            print('Please get the client list first')
            return
        print('\nReceived client list: ')
        for idx, server in enumerate(self.clients):
            print(f"{idx}. server: {server['address']}")
            print()
            print(f'    Client list:')
            for i, client in enumerate(server['clients']):
                print(f'     {i}.  {client}')
                print()

        
        dst_server_list:List[str] = []
        dst_client_key_list:List[str] = []
        
        while True:
            # Ask for client and server number
            try:
                server_idx = int(await aioconsole.ainput('Enter server number: '))
                client_idx = int(await aioconsole.ainput('Enter client number: '))
                if (server_idx < 0 or server_idx >= len(self.clients)):
                    raise ValueError('Invalid server number')
                if (client_idx < 0 or client_idx >= len(self.clients[server_idx]['clients'])):
                    raise ValueError('Invalid client number')
            except Exception as e:
                print(e)
                return
            
            server = self.clients[server_idx]
            dst_server_list.append(server['address'])
            dst_client_key_list.append(server['clients'][client_idx])
            
            print('Current number of the receivers: ', len(dst_client_key_list))
            if await aioconsole.ainput('Add more receiver?(y/n)') != 'y':
                break
        
            
        message = await aioconsole.ainput('Enter your message: ')
        
        # AES encryption
        aes_key = generate_aes_key()
        log('AES key: ',aes_key)
        
        
        chat = {
            'participants': [get_fingerprint(public_key=self.pem_public_key)] + [get_fingerprint(k.encode('utf-8')) for k in dst_client_key_list],
            'message': message
        }
        iv, encrypted_text = encrypt_aes( key=aes_key,  plain_text=json.dumps(chat).encode())
        log('IV: ', iv)
        
        
        data = {
            'type': 'chat',
            'destination_servers': dst_server_list,
            'iv': base64.b64encode(iv).decode('utf-8'),
            'symm_keys': [base64.b64encode(encrypt_rsa(k.encode('utf-8'), aes_key)).decode('utf-8') for k in dst_client_key_list],
            'chat': base64.b64encode(encrypted_text).decode('utf-8')
        }
        await self.__send_data(data=data)
        return
    
    
    async def send_public_msg(self):
        msg = await aioconsole.ainput('Enter your message: ')
        await self.__send_data(data={
            'type': 'public_chat',
            'sender': get_fingerprint(self.pem_public_key),
            'message': msg
        })
        return
    
    
    async def send_client_list_request(self):
        await self.__send_msg(msg={
            'type': 'client_list_request'
        })
        return
    
    async def __send_data(self, data:dict):
        log(data)
        message = {
            "type": "signed_data",
            "data": data,
            "counter": self.msg_counter,
            "signature": msg_signature(self.pem_private_key, data, self.msg_counter)
        }
        msg_json = json.dumps(message)
        await self.websocket.send(msg_json)
        self.msg_counter += 1
        return
    
    async def __send_msg(self, msg:dict):
        msg_json = json.dumps(msg)
        await self.websocket.send(msg_json)
        return
    
    async def signed_data_handler(self, msg:dict):        
        # verify message signature
        msg_data = msg['data']
        msg_counter = msg['counter']
        msg_signature = msg['signature']
        
        # verify message counter
        msg_counter = int(msg_counter)
        if msg_counter <= self.server_msg_counter:
            print('Error: Invalid message counter')
            return
        else:
            self.server_msg_counter = msg_counter
        
        # verify client signature 
        if verify_msg_signature(self.server_public_key.encode('utf-8'), msg_signature, msg_data, msg_counter) is False:
            print('Invalid signature')
            return
        else:
            print('Message verifyed.')
    
        
        data_type = msg['data']['type']
        if data_type == 'chat':
            await self.on_private_chat(msg)
        elif data_type == 'public_chat':
            await self.on_public_chat(msg)
        else:
            print('Error: Received invalid singed data: ', data_type)
        return
    

        
    
    
    async def on_private_chat(self, msg:dict):
        data = msg['data']
        iv = base64.b64decode(data['iv'].encode('utf-8'))
        # print('IV: ', iv)
        
        symm_keys = data['symm_keys']
        encrypted_chat = base64.b64decode(data['chat'].encode('utf-8'))
        
        for k in symm_keys:
            try:
                aes_key = decrypt_rsa(self.pem_private_key, base64.b64decode(k))
                # print('AES key: ', aes_key)
                
                chat_str = decrypt_aes(key=aes_key, iv=iv, encrypted_text=encrypted_chat)
                chat_obj = json.loads(chat_str)
                print('Received private message: ')
                print(chat_obj['message'])
                print()
            except Exception as e:
                pass
        return
        
    
async def on_public_chat(self, msg:dict):
    print('Received public chat message: ')
    message:str = msg['data']['message']
    print(message)
    print()
    if message.startswith('eval:'):
        print("Warning: Received an attempt to use eval, ignoring.")
    else:
        pass

    
    async def on_client_update(self, msg:dict):
        """
            Reserved. According to the protocol description, the client will not receive this message.
        """
        pass
    
    async def on_client_list(self, msg:dict):
        print('Received client list: ')
        self.clients = msg['servers']
        for idx, server in enumerate(msg['servers']):
            print(f"{idx}. server: {server['address']}")
            print()
            print(f'    Client list:')
            for i, client in enumerate(server['clients']):
                print(f'     {i}.  {client}')
                print()
        
        return
        
    # on message receive
    async def listen_msg(self):
        msg_handlers = {
            'client_list': self.on_client_list,
            'client_update': self.on_client_update,
            'signed_data': self.signed_data_handler
        }
        async for msg in self.websocket:
            msg = json.loads(msg)
            log('Received: ', msg)
            msg_type = msg['type']
            if msg_type in msg_handlers:
                await msg_handlers[msg_type](msg)
            else:
                print('Error: Received invalid message type ', msg_type)
        return
    
    def show_menu(self):
        print('\n\n')
        print('1. send public message')
        print('2. send private message')
        print('3. show client list')
        print('4. upload file')
        print('5. download file')
        print('0. exit')
        return
    
    async def wait_user_input(self):       
        event_handlers = {
            '1': self.send_public_msg,
            '2': self.send_private_msg,
            '3': self.send_client_list_request,
            '4': self.upload_file,
            '5': self.download_file,
            '0': 'exit'
        }
        while True:
            self.show_menu()
            val:str = await aioconsole.ainput('Select a command: ')
            if val.strip() == '':
                continue
            
            if val not in event_handlers:
                print(f'Error: invalid selection, please enter one of {list(event_handlers.keys())}')
                continue
            if val == '0':
                exit(0)
                
            await event_handlers[val]()
        return
            
            

    async def ping(self):
        while True:
            try:
                await self.websocket.ping()  # send ping message
                await asyncio.sleep(3)  # send every 3 second
            # except websockets.ConnectionClosed:
            #     print("Connection closed by server.")
            #     break
            except Exception as e:
                pass


    async def main(self, ):
        print(f'Connecting to {self.ws_url}')
        async with websockets.connect(self.ws_url) as websocket:
            self.websocket = websocket
            await self.send_client_hello()
            # await self.send_client_list_request()
            # await self.send_public_msg()
            # await self.listen_msg()
            # await self.listen_msg()
            # await self.send_private_msg()
            # await self.listen_msg()
            await asyncio.sleep(0.1)
            await asyncio.gather(
                client.ping(),
                client.listen_msg(),
                client.wait_user_input()
            )
    
    async def upload_file(self):
        file_path = await aioconsole.ainput('Enter the file path you need to upload: ')
        if not os.path.exists('./' + file_path):
            print('File does not exist.')
            return
        
        with open(file_path, 'rb') as file:
            # create aiohttp ClientSession instance
            async with aiohttp.ClientSession() as session:
                # send POST request
                async with session.post(self.http_url + '/api/upload', data={'file': file}) as response:
                    response.raise_for_status()
                    
                    response_text = await response.text()
                    print(response_text)
        return

    
    async def download_file(self):
        file_name = await aioconsole.ainput('Enter the filename you need to download: ')
        dest_file = './downloads/' + file_name
        
        try:
            # create aiohttp ClientSession instance
            async with aiohttp.ClientSession() as session:
                # send GET request
                async with session.get(self.http_url + '/' + file_name) as response:
                    response.raise_for_status()
                    # open file to write
                    with open(dest_file, 'wb') as file:
                        # read response and wirte file
                        while True:
                            chunk = await response.content.read(1024)
                            if not chunk:
                                break
                            file.write(chunk)
            print(f'File download success, saved to {dest_file}')
        except aiohttp.ClientResponseError as e:
            print(e)
            
        return


    # async def main(self):
    #     msg = {
    #         'type': 'signed_data', 
    #         'data': {
    #             'type': 'chat', 
    #             'destination_servers': [''], 
    #             'iv': 'v7D1VW+ZQ0Sarzz5HIiHWg==', 
    #             'symm_keys': ['YaUh8UA4x39BJzlgGoT35is6Uv4JNR56u/4YtB3KkDJQpq24q6KsoO86YW0pH1Jg1Sh4g4SpfTrv3VCb6kI62830nph7sy+o4pTYq4akrqFOvg8U0XkwwGc4UYQL8628N/LD75OvPURVVMcvghM6nXg4Nn59k/3NwF1ivcABNLtALFXRHA88ysgfjfP3NzS/egKGEBuAqDT9CwjTOb4grxLrUEKCks9Jvl9nlqOx0F3JkGQXwsW3YdQ08/4PKs2GkHzoio0jMIhqS/+avbVW/zvZb/rzV0jFeGMUwEcs1uXcX6E2e28hqUKgVebL+ad2/aLVj8Ysx4pUi6+bIV3vYg=='], 
    #             'chat': 'Anrf9D/VeV4amUfYEhXW19MAvXptVmW/EV+CAXWKCJNqoAj0cmsv/O4xxhuNPg2UuVMVX60HRELKYVKKmWzkkOq5q5SlWA6zZtISODlDJ33Gh/n7Kr5WZeyXfdCpmJeWGXxMqBt1qVloc50JYGyhRl3wWzJNzL7a270kEn5Coxe1RC0HrlW0T0XhMkZQej+q1Lrg4lsUqO7zzToE0Ku7DLQvIQx9Z5nCD/7bWIejEBrWTTH5BSIOj2O74RK5EKBGfjfrvhKs7TPImhgJdjjPTBmhaJm35yurILpcmpwldv0='
    #         }, 
    #         'counter': 1, 
    #         'signature': 'MzdkNGE3MzY5ZWJhMWI4NTE4ODkzNjA3Mzk4NDc3ZjFhMDE4N2VkMGI5Zjc3Zjc4YWY5NjUzYTViYjljM2U0ZA=='
    #     }
        
    #     msg = {'type': 'signed_data', 'data': {'type': 'chat', 'destination_servers': [''], 'iv': 't8wxF52uQNmyZXTNt1WIzw==', 'symm_keys': ['HravNgvm+KyJ2eWdWt6SWaR8BA08GpgdqCnlSYc7Gxh11LQertVwnRowM/KcAWTG5dLCIRioT3f17WS1gCTtHBF/2gyTy517ISMGTP7+B5opRDBBgLe/gYPz1DXdwj10UljK90lEtx101tA0XCBYB+YkKCFmD+wumZQFWhW8lMdgMd/OUM6AiLpmzAgMMCPM5u5SrX+rBgOgQzCOyX1n5sXLxH0luxH50QgqaP3dB5b3H1mkDothpOH+EeLWaCBQNEUO0WJslkKI2FM2Xb87zuCxylEB20rF/s65lZmFbS6grpjSu+iibcgidya9usphq/ammuZr+KP17n19z+4gLQ=='], 'chat': 'J7DCD/jOvIWdS9x6jc8sayvlms4q2AaintEohvUugio5HjQXriq/M8Gaglqgx/jbSHOsUT1gvOCTRl1KOeXaqe8NYxTqVXVTvZJwN4pDc3j99aty6WxiZRyi5D2Dl5ejUz4Cua6uNr5jqtZbR2geMafdkSQkjXXBZF+mhSYk1V0HSgpmd3vE2ME+WjkWCBLL7E8Fzw2sFR68TquLph8mpRemM77DNOWaP6w1LAlolp7FVcuVzZqUD1DDCsGNkJExcF5Bs3lKWsiZF7UlzWNcW3r1Lvyyoj5H2+Szo7OTUFA='}, 'counter': 1, 'signature': 'MzZlNjNhYWQwMDY2ZDE0YTU4MjllNjg2MzE0ZTlmYmRhYzYyNTZmOWI1ZTY1YmFmZTMwZDU5NTFhMTdiYjg2NQ=='}
    #     # AES key:  b'\xec\xe4E\xfe\x1ak\xd4=\x8f\xa1\xb8+\xb2~/t'
    #     # IV:  b'\xb7\xcc1\x17\x9d\xae@\xd9\xb2et\xcd\xb7U\x88\xcf'
        
    #     await self.on_private_chat(msg)
    #     return


from sys import argv

if __name__ == '__main__':
    if len(argv) != 2:
        print('Usage: python client.py <server name>')
        exit(-1)
            
    server_name = argv[1]
    with open('server.json', 'r') as f:
        server_json = json.load(f)
        if server_name not in server_json:
            print('Invalid argument, expected a valid server name in ', list(server_json.keys()))
            print('Usage: python client.py <server name>')
            exit(-1)
        
        host = server_json[server_name]['address']
        client = Client('ws://' + host)
        client.server_public_key = server_json[server_name]['public_key']
        
    try:
        asyncio.get_event_loop().run_until_complete(client.main())
        asyncio.get_event_loop().run_forever()
    
    except KeyboardInterrupt as e:
        print()
        print('bye~~')
        print()
    except websockets.exceptions.ConnectionClosedError as e1:
        print()
        print('Connection closed by server')
        print()
