import asyncio
import websockets
from typing import Dict, List
import json
from sys import argv
from aiohttp import web
import os
from tools import *
import os


'''
    Connection context
'''
class Context:
    def __init__(self, websocket) -> None:
        self.websocket:web.WebSocketResponse | websockets.WebSocketClientProtocol = websocket
        self.client_public_key:str = None
        
        # for neighbour connection
        self.neighbour_public_key:str = None
        self.clients = []
        self.address:str = ''
        self.prev_msg_counter = -1


'''
    The information of the server
'''
class ServerInfo:
    def __init__(self, address, port) -> None:
        self.address:str = address
        self.port:int = port
        self.public_key:str = None
        self.private_key:str = None
        self.msg_counter:int = 0

# key: client's public key
# vlaue: client's connection context
clients:Dict[bytes, Context] = {}

# key: server's address
# value: server's connection context
neighbours:Dict[str, Context] = {}
serverInfo = ServerInfo(address='', port=1234)





async def forward_msg(ctx:Context, msg:dict):
    data = msg['data']
    await __send_data(ctx, data)
    return

async def send_msg(ctx:Context, msg:Dict):
    """
        Send message to the connection

    Args:
        ctx (Context): connection context
        msg (Dict): message to send
    """
    log("Send: ", msg)
    msg_json = json.dumps(msg)
    
    # send message using difference interface
    if type(ctx.websocket) == web.WebSocketResponse:
        await ctx.websocket.send_str(msg_json)
    elif type(ctx.websocket) == websockets.WebSocketClientProtocol:
        await ctx.websocket.send(msg_json)
    else:
        print('Error: invalid type of websocket ', type(ctx.websocket))
    return

async def handle_client_hello(ctx:Context, msg:Dict):
    rsa_public_key = msg['data']['public_key']
    ctx.client_public_key = rsa_public_key
    
    # store client connection context
    clients[rsa_public_key] = ctx
    await send_client_update()
    return

async def handle_chat(ctx:Context, msg:Dict):
    data = msg['data']
    destination_servers = data['destination_servers']
    
    sent_server = []
    # message sent from client
    if ctx.client_public_key is not None:
        for server_addr in destination_servers:
            if server_addr in sent_server:
                # Ensure that each client just receive one message
                continue
            
            if server_addr == serverInfo.address:
                # send to all clients
                for client_ctx in clients.values():
                    await forward_msg(client_ctx, msg)
                    
            elif server_addr in neighbours and server_addr:
                # send to neighbours
                server_ctx = neighbours[server_addr]
                await forward_msg(server_ctx, msg)
                
            else:
                # invalid destination server
                print('Invalid destination server')
            sent_server.append(server_addr)
    
    # message sent from other server    
    if ctx.neighbour_public_key is not None:
        # send to all clients
        for client_ctx in clients.values():
            await forward_msg(client_ctx, msg)
    
    # print(ctx.neighbour_public_key, ctx.client_public_key)
    return

async def handle_public_chat(ctx:Context, msg:Dict):
    data = msg['data']
    # send to all clients directly connected to homeserver
    for client_ctx in clients.values():
        await forward_msg(client_ctx, msg)
    
    # send to all neighbour if current context is from a user
    if ctx.client_public_key is not None:
        for neighbour_ctx in neighbours.values():
            await forward_msg(neighbour_ctx, msg)
    return

async def handle_client_list_request(ctx:Context, msg:Dict):
    servers = [{
        'address': serverInfo.address,
        'clients': list(clients.keys())
    }]

    servers += [{'address': n.address,'clients': n.clients} for n in neighbours.values()]
    response = {
        "type": "client_list",
        "servers": servers
    }
    # send response
    await send_msg(ctx, response)
    return   


async def send_client_update():
    # send client update to all neighbour
    resposne = {
        "type": "client_update",
        "clients": [ctx.client_public_key for ctx in clients.values()]
    }
    # send to all neighbours
    for neighbour_ctx in neighbours.values():
        await send_msg(neighbour_ctx, resposne)
        
    return

async def handle_client_update(ctx:Context, msg:Dict):
    new_clients = msg.get('clients', None)
    if clients is not None:
        ctx.clients = new_clients
        print(f'Client updated from {ctx.address}')
    else:
        print('Error: invalid client update message.')
    return

async def handle_client_update_request(ctx:Context, msg:Dict):
    # send client list to neighbour
    resposne = {
        "type": "client_update",
        "clients": [ctx.client_public_key for ctx in clients.values()]
    }
    
    await send_msg(ctx, resposne)
    return


async def handle_server_hello(ctx:Context, msg:Dict):
    sender = msg['data']['sender']
    print('server hello: ', sender)
    
    # Read the server's public key from the message
    incoming_public_key = msg['data'].get('public_key', None)
    if not incoming_public_key:
        print("Error: server_hello message is missing public key")
        return

    # Load the expected public key from the configuration (server.json)
    with open('server.json', 'r') as f:
        server_json = json.load(f)
    expected_server_info = next((server for server in server_json.values() if server['address'] == sender), None)
    
    if expected_server_info and expected_server_info['public_key'] == incoming_public_key:
        # If the public key matches, proceed
        ctx.address = sender
        ctx.neighbour_public_key = incoming_public_key
        neighbours[sender] = ctx
        print(f"Connection verified with {sender}")
    else:
        # If the public key does not match, reject the connection
        print(f"Error: Public key mismatch or unrecognized server: {sender}")
        return

    
    
async def handle_signed_data(ctx:Context, msg:Dict):
    msg_data = msg['data']
    msg_counter = msg['counter']
    msg_signature = msg['signature']
    
    # verify message counter
    msg_counter = int(msg_counter)
    if msg_counter <= ctx.prev_msg_counter:
        print('Error: Invalid message counter')
        return
    else:
        ctx.prev_msg_counter = msg_counter
    
    if ctx.client_public_key is not None:
        # verify client signature 
        if verify_msg_signature(ctx.client_public_key.encode('utf-8'), msg_signature, msg_data, msg_counter) is False:
            print('Invalid signature')
            return
        else:
            print('Message verifyed.')        
    
    data_type = msg['data']['type']
    data_handlers = {
        'hello': handle_client_hello, 
        'chat': handle_chat, 
        'public_chat': handle_public_chat,
        'server_hello': handle_server_hello
    }
    if data_type not in data_handlers:
        raise ValueError(f'Unsupport data.type: {data_type}')
    
    handler = data_handlers[data_type]
    await handler(ctx, msg)
    return
        

async def handle_message(ctx:Context, msg:Dict):
    msg_type = msg['type']
    handlers = {
        'signed_data': handle_signed_data,
        'client_list_request': handle_client_list_request,
        'client_update': handle_client_update,
        'client_update_request': handle_client_update_request,
        'client_update': handle_client_update,
    }
    if msg_type in handlers:
        await handlers[msg_type](ctx, msg)
        return
    else:
        print('Received invalid type of message: ', msg_type)
    return


async def send_server_hello(ctx:Context):
    data = {
        'type': 'server_hello',
        'sender': serverInfo.address
    }
    await __send_data(ctx, data)
    return


async def __send_data(ctx:Context, data:dict):
    message = {
        "type": "signed_data",
        "data": data,
        "counter": serverInfo.msg_counter,
        "signature": msg_signature(serverInfo.private_key.encode('utf-8'), data, serverInfo.msg_counter)
    }
    await send_msg(ctx, message)
    serverInfo.msg_counter += 1
    return


async def connect_neighbour(current_server_name:str, server_json:dict):
    print('Connecting to neighbours... ')
    for server_name, server in server_json.items():
        addr = server['address']
        if addr == current_server_name:
            continue
        
        try:
            # connect to neighbour
            conn = await websockets.connect("ws://" + addr)
            ctx = Context(websocket=conn)
            ctx.address = addr
            ctx.neighbour_public_key = server['public_key']
            
            # send server hello
            await send_server_hello(ctx)
            neighbours[addr] = ctx
            print('Connected to ', addr, ' success.')
            
        
        except ConnectionRefusedError as e:
            # neighbour close this connection
            continue
    return



async def listen_neighbour_msg(ctx:Context):
    async for msg in ctx.websocket:
        msg_json = json.loads(msg)
        await handle_message(ctx, msg_json)
        
    return



async def echo(request:web.Request):
    """
        Accept new websocket connection
    """
    websocket = web.WebSocketResponse()
    await websocket.prepare(request)
    
    # create connection context
    ctx = Context(websocket=websocket)
    
    try:
        async for message in websocket:
            # For debug
            log("Received:", message.data)
            message = json.loads(message.data)
            await handle_message(ctx=ctx, msg=message)
            print('\n\n')
    except websockets.exceptions.ConnectionClosedError as e:
        pass
    
    except AttributeError as e:
        pass
    
    print('socket close')
    if ctx.client_public_key is not None and ctx.client_public_key in clients:
        # remove client
        clients.pop(ctx.client_public_key)
        await send_client_update()
        print('client removed and send client_update')
    if ctx.neighbour_public_key is not None and ctx.address in neighbours:
        # remove neighbour
        neighbours.pop(ctx.address)
        print('remove neighoubr success')
    
    return websocket


async def file_upload_handler(request):
    reader = await request.multipart()
    while True:
        part = await reader.next()
        if part.name == 'file' and part.filename:
            # get file name
            filename = part.filename
            content = await part.read(decode=True)
            # save file 
            with open(os.path.join('uploads', filename), 'wb') as f:
                f.write(content)
            
            print(f'File {filename} uploaded successfully.')
            return web.Response(text=f'File {filename} uploaded successfully.')
        elif part.name is None:
            break
    return web.Response(text='No file uploaded.')




async def file_download_handler(request):
    filename = request.match_info['filename']
    
    base_directory = './uploads/'
    safe_file_path = os.path.normpath(os.path.join(base_directory, filename))
    
    if not safe_file_path.startswith(os.path.abspath(base_directory)):
        print('Illegal file path: ', safe_file_path)
        return web.Response(text='Illegal file path', status=400)
    
    if os.path.exists(safe_file_path):
        with open(safe_file_path, 'rb') as f:
            response = web.Response(body=f.read())
            response.headers['Content-Type'] = 'application/octet-stream'
            response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'
            print(f'File {filename} sent to client')
            return response
    else:
        print('File not found: ', safe_file_path)
        return web.Response(text='File not found', status=404)




async def main():
    if len(argv) != 2:
        print('Usage: python server.py <server name>')
        return
    
    server_name = argv[1]
    with open('server.json', 'r') as f:
        server_json:dict = json.load(f)
        
    if server_name not in server_json:
        print('Invalid argument, expected a valid server name in ', list(server_json.keys()))
        print('Usage: python server.py <server name>')
        exit(-1)
        

    
    # get current server's address and port and key pairs
    server = server_json[server_name]
    [addr, port] = server['address'].split(':')
    serverInfo.address = server['address']
    serverInfo.port = port
    serverInfo.public_key = server['public_key']
    serverInfo.private_key = server['private_key']
    
    
    # connect neighbour
    await connect_neighbour(server_name, server_json)
    
    print(f'Server running on ws://{addr}:{port}')
    

        
    # web
    app = web.Application()
    app.add_routes([
        web.post('/api/upload', file_upload_handler), 
        web.get('/{filename}', file_download_handler),
        web.get('/', echo)
    ])
    
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '0.0.0.0', port)
    
    # Listen for neighbour's websocket message
    features = [listen_neighbour_msg(c) for c in neighbours.values()]
    
    asyncio.gather(
        site.start(),
        *features
    )
    return


if __name__ == '__main__':
    try:
        asyncio.get_event_loop().run_until_complete(main())

        asyncio.get_event_loop().run_forever()
    except KeyboardInterrupt as e:
        print()
        print('bye~~')
        print()