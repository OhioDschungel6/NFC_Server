from socketserver import ThreadingTCPServer, StreamRequestHandler, TCPServer
from Crypto.Cipher import DES3
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# 3DES-Key (This is the standard key according to the NPX specification)
key3DES = bytearray(
    [0x49, 0x45, 0x4D, 0x4B, 0x41, 0x45, 0x52, 0x42, 0x21, 0x4E, 0x41, 0x43, 0x55, 0x4F, 0x59, 0x46, 0x49, 0x45, 0x4D,
     0x4B, 0x41, 0x45, 0x52, 0x42])
key3DES = bytearray(
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00])
# Default AES-Key
keyAES = bytearray([0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0])
unitTest = False
debug = False


class Authentifier(StreamRequestHandler):
    def handle(self: StreamRequestHandler):
        mode = self.rfile.read(1)
        if (mode[0] == 0):
            print("2K3DES Auth")
            handle2K3DESAuth(self)
        elif (mode[0] == 1):
            print("3K3DES Auth")
            handle3K3DESAuth(self)
        elif (mode[0] == 2):
            print("AES Auth")
            handleAESAuth(self)


def handle2K3DESAuth(handler: StreamRequestHandler):
    # Step 0: Get ID
    UID = handler.rfile.read(7)
    if (debug):
        print("UID")
        print(''.join('{:02x}'.format(x) for x in UID))
    # Step 3
    decryptor = DES3.new(key3DES, DES3.MODE_CBC, iv=bytearray(8))
    ekRndB = handler.rfile.read(8)  # ek(RndB)
    if (debug):
        print("ekRndB")
        print(''.join('{:02x}'.format(x) for x in ekRndB))
    RndA = get_random_bytes(8)
    if(unitTest):
        RndA = bytearray([0xC9 ,0x6C ,0xE3 ,0x5E ,0x4D ,0x60 ,0x87 ,0xF2])
    if (debug):
        print("RndA")
        print(''.join('{:02x}'.format(x) for x in RndA))
    RndB = bytearray(decryptor.decrypt(ekRndB))
    if (debug):
        print("RndB")
        print(''.join('{:02x}'.format(x) for x in RndB))
    RndBPrime = RndB[1:8] + RndB[0:1]
    RndARndBPrime = RndA + RndBPrime
    encryptor = DES3.new(key3DES, DES3.MODE_CBC, iv=ekRndB)
    ekRndARndBPrime = encryptor.encrypt(RndARndBPrime)
    if (debug):
        print("ekRndARndBPrime")
        print(''.join('{:02x}'.format(x) for x in ekRndARndBPrime))
    handler.wfile.write(ekRndARndBPrime)
    handler.wfile.flush()
    # Step5
    ekRndAPrime = handler.rfile.read(8)
    if (debug):
        print("ekRndAPrime")
        print(''.join('{:02x}'.format(x) for x in ekRndAPrime))
    decryptor = DES3.new(key3DES, DES3.MODE_CBC, iv=ekRndARndBPrime[8:16])
    RndAPrime = decryptor.decrypt(ekRndAPrime)
    RndAPrime2 = RndA[1:8] + RndA[0:1]
    if (debug):
        print("ekRndAPrime")
        print(''.join('{:02x}'.format(x) for x in RndAPrime))
    if (RndAPrime == RndAPrime2):
        print("Authentificated succesfully")
        SessenKey = RndA[0:4] + RndB[0:4] + RndA[4:8] + RndB[4:8]
        if(key3DES[0:8] == key3DES[8:16]):
            SessenKey = RndA[0:4] + RndB[0:4] + RndA[0:4] + RndB[0:4]

        if (debug):
            print("SessenKey")
            print(''.join('{:02x}'.format(x) for x in SessenKey))
        handler.wfile.write(SessenKey)
        handler.wfile.flush()
    else:
        print("Error")

def handle3K3DESAuth(handler: StreamRequestHandler):
    # Step 0: Get ID
    UID = handler.rfile.read(7)
    if (debug):
        print("UID")
        print(''.join('{:02x}'.format(x) for x in UID))
    # Step 3
    decryptor = DES3.new(key3DES, DES3.MODE_CBC, iv=bytearray(8))
    ekRndB = handler.rfile.read(16)  # ek(RndB)
    if (debug):
        print("ekRndB")
        print(''.join('{:02x}'.format(x) for x in ekRndB))
    RndA = get_random_bytes(16)
    if(unitTest):
        RndA = bytearray([0x36 ,0xC5 ,0xF8 ,0xBF ,0x4A ,0x09 ,0xAC ,0x23 ,0x9E ,0x8D ,0xA0 ,0xC7 ,0x32 ,0x51, 0xD4 ,0xAB])
    if (debug):
        print("RndA")
        print(''.join('{:02x}'.format(x) for x in RndA))
    RndB = bytearray(decryptor.decrypt(ekRndB))
    if (debug):
        print("RndB")
        print(''.join('{:02x}'.format(x) for x in RndB))
    RndBPrime = RndB[1:16] + RndB[0:1]
    RndARndBPrime = RndA + RndBPrime
    encryptor = DES3.new(key3DES, DES3.MODE_CBC, iv=ekRndB[8:16])
    ekRndARndBPrime = encryptor.encrypt(RndARndBPrime)
    if (debug):
        print("ekRndARndBPrime")
        print(''.join('{:02x}'.format(x) for x in ekRndARndBPrime))
    handler.wfile.write(ekRndARndBPrime)
    handler.wfile.flush()
    # Step5
    ekRndAPrime = handler.rfile.read(16)
    if (debug):
        print("ekRndAPrime")
        print(''.join('{:02x}'.format(x) for x in ekRndAPrime))
    decryptor = DES3.new(key3DES, DES3.MODE_CBC, iv=ekRndARndBPrime[24:32])
    RndAPrime = decryptor.decrypt(ekRndAPrime)
    RndAPrime2 = RndA[1:16] + RndA[0:1]
    if (debug):
        print("RndAPrime")
        print(''.join('{:02x}'.format(x) for x in RndAPrime))
    if (RndAPrime == RndAPrime2):
        print("Authentificated succesfully")
        SessenKey = RndA[0:4] + RndB[0:4] + RndA[6:10] + RndB[6:10] +RndA[12:16] + RndB[12:16]
        if (debug):
            print("SessenKey")
            print(''.join('{:02x}'.format(x) for x in SessenKey))
        handler.wfile.write(SessenKey)
        handler.wfile.flush()
    else:
        print("Error")


def handleAESAuth(handler: StreamRequestHandler):
    # Step 0: Get ID
    UID = handler.rfile.read(7)
    if (debug):
        print("UID")
        print(''.join('{:02x}'.format(x) for x in UID))

    # Step 3
    decryptor = AES.new(keyAES, AES.MODE_CBC, bytearray(16))
    ekRndB = handler.rfile.read(16)  # ek(RndB)
    if (debug):
        print("ekRndB")
        print(''.join('{:02x}'.format(x) for x in ekRndB))
    RndA = get_random_bytes(16)
    if(unitTest):
        RndA = bytearray([0xF4 ,0x4B ,0x26 ,0xF5 ,0x68 ,0x6F ,0x3A ,0x39 ,0x1C ,0xD3 ,0x8E ,0xBD ,0x10 ,0x77 ,0x22 ,0x81])
    if (debug):
        print("RndA")
        print(''.join('{:02x}'.format(x) for x in RndA))
    RndB = bytearray(decryptor.decrypt(ekRndB))
    if (debug):
        print("RndB")
        print(''.join('{:02x}'.format(x) for x in RndB))
    RndBPrime = RndB[1:16] + RndB[0:1]
    RndARndBPrime = RndA + RndBPrime
    encryptor = AES.new(keyAES, AES.MODE_CBC, iv=ekRndB)
    ekRndARndBPrime = encryptor.encrypt(RndARndBPrime)
    if (debug):
        print("ekRndARndBPrime")
        print(''.join('{:02x}'.format(x) for x in ekRndARndBPrime))
    handler.wfile.write(ekRndARndBPrime)
    handler.wfile.flush()
    # Step5
    ekRndAPrime = handler.rfile.read(16)
    if (debug):
        print("ekRndAPrime")
        print(''.join('{:02x}'.format(x) for x in ekRndAPrime))
    decryptor = AES.new(keyAES, AES.MODE_CBC, iv=ekRndARndBPrime[16:32])
    RndAPrime = decryptor.decrypt(ekRndAPrime)
    RndAPrime2 = RndA[1:16] + RndA[0:1]
    if (debug):
        print("RndAPrime")
        print(''.join('{:02x}'.format(x) for x in RndAPrime))
        print("RndAPrime2")
        print(''.join('{:02x}'.format(x) for x in RndAPrime2))
    if (RndAPrime == RndAPrime2):
        print("Authentificated succesfully")
        SessenKey = RndA[0:4] + RndB[0:4] + RndA[12:16] + RndB[12:16]
        if (debug):
            print("SessenKey")
            print(''.join('{:02x}'.format(x) for x in SessenKey))
        handler.wfile.write(SessenKey)
        handler.wfile.flush()
    else:
        print("Error")


if __name__ == '__main__':
    webServer = ThreadingTCPServer(("", 80), Authentifier)
    print("Started")
    webServer.serve_forever()
