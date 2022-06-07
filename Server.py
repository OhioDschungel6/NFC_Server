from socketserver import ThreadingTCPServer, StreamRequestHandler, TCPServer
from Crypto.Cipher import DES3
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# 3DES-Key (This is the standard key according to the NPX specification)
key3DES = bytearray([0x49, 0x45, 0x4D, 0x4B, 0x41, 0x45, 0x52, 0x42, 0x21, 0x4E, 0x41, 0x43, 0x55, 0x4F, 0x59, 0x46, 0x49, 0x45, 0x4D,
       0x4B, 0x41, 0x45, 0x52, 0x42])

# Default AES-Key
keyAES = bytearray([0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0])

class Authentifier(StreamRequestHandler):
    def handle(self:StreamRequestHandler):
        device = self.rfile.read(1)
        if(device[0] == 0):
            handleUltralightC(self)
        elif(device[0] == 1):
            handleDesfire(self)


def handleUltralightC(handler:StreamRequestHandler):
    # Step 0: Get ID
    UID = handler.rfile.read(7)
    # print("UID")
    # print (''.join('{:02x}'.format(x) for x in UID))
    # Step 3
    print("Received message")
    decryptor = DES3.new(key3DES, DES3.MODE_CBC, iv=bytearray(8))
    ekRndB = handler.rfile.read(8)  # ek(RndB)
    # print("ekRndB")
    # print (''.join('{:02x}'.format(x) for x in ekRndB))
    RndA = get_random_bytes(8)
    # print("RndA")
    # print (''.join('{:02x}'.format(x) for x in RndA))
    RndB = bytearray(decryptor.decrypt(ekRndB))
    RndBPrime = RndB[1:8] + RndB[0:1]
    RndARndBPrime = RndA + RndBPrime
    encryptor = DES3.new(key3DES, DES3.MODE_CBC, iv=ekRndB)
    ekRndARndBPrime = encryptor.encrypt(RndARndBPrime)
    # print("ekRndARndBPrime")
    # print (''.join('{:02x}'.format(x) for x in ekRndARndBPrime))
    handler.wfile.write(ekRndARndBPrime)
    handler.wfile.flush()
    # Step5
    ekRndAPrime = handler.rfile.read(8)
    # print("ekRndAPrime")
    # print (''.join('{:02x}'.format(x) for x in ekRndAPrime))
    decryptor = DES3.new(key3DES, DES3.MODE_CBC, iv=ekRndARndBPrime[8:16])
    RndAPrime = decryptor.decrypt(ekRndAPrime)
    RndAPrime2 = RndA[1:8] + RndA[0:1]
    # print("RndAPrime")
    # print (''.join('{:02x}'.format(x) for x in RndAPrime))
    # print("RndAPrime2")
    # print (''.join('{:02x}'.format(x) for x in RndAPrime2))
    if (RndAPrime == RndAPrime2):
        print("Authentificated succesfully")
    else:
        print("Error")

def handleDesfire(handler: StreamRequestHandler):
    # Step 0: Get ID
    debug = True
    UID = handler.rfile.read(7)
    if(debug):
        print("UID")
        print (''.join('{:02x}'.format(x) for x in UID))


    # Step 3
    print("Received message")
    decryptor = AES.new(keyAES,AES.MODE_CBC, bytearray(16))
    ekRndB = handler.rfile.read(16)  # ek(RndB)
    if(debug):
        print("ekRndB")
        print (''.join('{:02x}'.format(x) for x in ekRndB))
    RndA = get_random_bytes(16)
    # RndA = bytearray([0xF4 ,0x4B ,0x26 ,0xF5 ,0x68 ,0x6F ,0x3A ,0x39 ,0x1C ,0xD3 ,0x8E ,0xBD ,0x10 ,0x77 ,0x22 ,0x81]);
    if(debug):
        print("RndA")
        print (''.join('{:02x}'.format(x) for x in RndA))
    RndB = bytearray(decryptor.decrypt(ekRndB))
    if(debug):
        print("RndB")
        print (''.join('{:02x}'.format(x) for x in RndB))
    RndBPrime = RndB[1:16] + RndB[0:1]
    RndARndBPrime = RndA + RndBPrime
    encryptor = AES.new(keyAES, AES.MODE_CBC, iv=ekRndB)
    ekRndARndBPrime = encryptor.encrypt(RndARndBPrime)
    if(debug):
        print("ekRndARndBPrime")
        print (''.join('{:02x}'.format(x) for x in ekRndARndBPrime))
    handler.wfile.write(ekRndARndBPrime)
    handler.wfile.flush()
    # Step5
    ekRndAPrime = handler.rfile.read(16)
    if(debug):
        print("ekRndAPrime")
        print (''.join('{:02x}'.format(x) for x in ekRndAPrime))
    decryptor = AES.new(keyAES, AES.MODE_CBC, iv=ekRndARndBPrime[16:32])
    RndAPrime = decryptor.decrypt(ekRndAPrime)
    RndAPrime2 = RndA[1:16] + RndA[0:1]
    if(debug):
        print("RndAPrime")
        print (''.join('{:02x}'.format(x) for x in RndAPrime))
        print("RndAPrime2")
        print (''.join('{:02x}'.format(x) for x in RndAPrime2))
    if (RndAPrime == RndAPrime2):
        print("Authentificated succesfully")
    else:
        print("Error")


if __name__ == '__main__':
    webServer = ThreadingTCPServer(("", 80), Authentifier)
    print("Started")
    webServer.serve_forever()
