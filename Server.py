from socketserver import ThreadingTCPServer, StreamRequestHandler, TCPServer
from Crypto.Cipher import DES3
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Random import get_random_bytes
import sqlite3
import zlib

DEFAULT_KEY = bytearray(
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00])

DEFAULT_3DES_KEY = bytearray(
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00])
# Default AES-Key
DEFAULT_AES_KEY = bytearray([0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0])

KEYTYPE_2K3DES = 0x00
KEYTYPE_3K3DES = 0x20
KEYTYPE_AES = 0x80

KEYLENGTH = {
    KEYTYPE_2K3DES: 24,
    KEYTYPE_3K3DES: 24,
    KEYTYPE_AES: 16
}
ROUNDSIZE = {
    KEYTYPE_2K3DES: 8,
    KEYTYPE_3K3DES: 16,
    KEYTYPE_AES: 16
}

BLOCKSIZE = {
    KEYTYPE_2K3DES: 8,
    KEYTYPE_3K3DES: 8,
    KEYTYPE_AES: 16
}

TESTDATA = {
    KEYTYPE_2K3DES: bytearray([0xC9, 0x6C, 0xE3, 0x5E, 0x4D, 0x60, 0x87, 0xF2]),
    KEYTYPE_3K3DES: bytearray(
        [0x36, 0xC5, 0xF8, 0xBF, 0x4A, 0x09, 0xAC, 0x23, 0x9E, 0x8D, 0xA0, 0xC7, 0x32, 0x51, 0xD4, 0xAB]),
    KEYTYPE_AES: bytearray(
        [0xF4, 0x4B, 0x26, 0xF5, 0x68, 0x6F, 0x3A, 0x39, 0x1C, 0xD3, 0x8E, 0xBD, 0x10, 0x77, 0x22, 0x81])
}

sessionKeys = {}

unitTest = False
debug = False


class ConnectionHandler(StreamRequestHandler):
    def handle(self: StreamRequestHandler):
        mode = self.rfile.read(1)
        if (mode[0] == 0xC4):
            print("Change key")
            changeKey(self)
        elif (mode[0] == 0xAA):
            print("Authenticate")
            authenticate(self)
        elif (mode[0] == 0x6A):
            print("GetAppId")
            getAppId(self)
        elif (mode[0] == 0x4A):
            print("Verify android")
            verifyAndroid(self)


# def verifyAndroid(handler: StreamRequestHandler):
def verifyAndroid():
    signedData = bytes([ 48, 68, 2, 32, 122, 235, 48, 169, 0, 119, 114,172, 15, 13, 6, 147, 112, 122, 144, 145, 184, 37, 136, 92, 90, 168, 214, 67, 112, 155, 129, 98, 130, 201, 173, 158, 2, 32, 25, 239, 199, 129, 227, 184, 229, 171, 21, 47, 66, 201, 54, 93, 110, 15, 249, 234, 199, 60, 208, 21, 142, 96, 226, 110, 145, 103, 152, 152, 5, 202])
    pk = bytearray([ 48, 89, 48, 19, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 8, 42, 134, 72, 206, 61, 3, 1, 7, 3, 66, 0, 4, 64, 106, 232, 62, 2, 226, 36, 192, 150, 174, 242, 18, 168, 239, 191, 116, 21, 112, 193, 110, 220, 251, 217, 67, 144, 126, 128, 230, 106, 171, 215, 29, 21, 17, 103, 221, 12, 143, 195, 241, 134, 56, 58, 242, 198, 235, 200, 6, 124, 120, 217, 111, 140, 213, 8, 65, 195, 139, 143, 149, 80, 155, 40, 2])
    publicKey = ECC.import_key(pk,)
    dataToSign = bytearray([0,0,0,0,0,0,0,0])

    print("pk")
    print(''.join('{:02x}'.format(x) for x in pk))
    print("signedData")
    print(''.join('{:02x}'.format(x) for x in signedData))
    print("publicKey")
    print(''.join('{:02x}'.format(x) for x in publicKey.export_key(format = 'DER')))

    # userId = handler.rfile.read(8) #TODO
    # dataToSign = get_random_bytes(16)
    # handler.wfile.write(dataToSign)
    # publicKey = 1 #TODO getPublicKey
    # signedDataLength = handler.rfile.read(1)[0]
    # signedData = handler.rfile.read(signedDataLength)

    hashedDataToSign = SHA256.new(dataToSign)
    verifier = DSS.new(publicKey, 'fips-186-3', encoding='der')
    try:
        verifier.verify(hashedDataToSign, signedData)
        print("Android auth succesful.")
    except ValueError as error:
        print("Android auth failed.")
        print(error)


def changeKey(handler: StreamRequestHandler):
    keytype = handler.rfile.read(1)[0]
    UID = handler.rfile.read(7)
    appId = handler.rfile.read(3)
    nameLength = handler.rfile.read(1)[0]
    name = handler.rfile.read(nameLength)
    if UID not in sessionKeys:
        return
    if keytype not in KEYLENGTH:
        return
    if keytype == KEYTYPE_2K3DES:
        return
    keylength = KEYLENGTH[keytype]
    isSameKey = True  # If another key than 0 should be changed in the future lol
    buffer = []
    keyVersion = 0x01
    keyNr = 0
    key = get_random_bytes(keylength)
    # key = bytearray([0x00 ,0x10 ,0x20 ,0x30 ,0x40 ,0x50 ,0x60 ,0x70 ,0x80 ,0x90 ,0xA0 ,0xB0 ,0xB0 ,0xA0 ,0x90 ,0x80])
    if appId == bytes(3):
        keyNr |= keytype
        key = bytes(keylength)
    cmd = [0xC4, keyNr]

    buffer.extend(key)
    if not isSameKey:
        # Currently not supported
        return
    if keytype == KEYTYPE_AES:
        buffer.append(keyVersion)
    crc32 = (zlib.crc32(bytes(cmd + buffer)) ^ 0xffffffff).to_bytes(4, byteorder="little")
    buffer.extend(crc32)
    if not isSameKey:
        # Currently not supported
        return
    (authType, sessionKey) = sessionKeys[UID]
    blockSize = BLOCKSIZE[authType]
    lastBlockSize = (len(buffer) % blockSize)
    if lastBlockSize != 0:
        buffer.extend(bytes(blockSize - lastBlockSize))

    if authType == KEYTYPE_2K3DES:
        encryptor = DES3.new(sessionKey, DES3.MODE_CBC, iv=bytearray(8))
    elif authType == KEYTYPE_3K3DES:
        encryptor = DES3.new(sessionKey, DES3.MODE_CBC, iv=bytearray(8))
    elif authType == KEYTYPE_AES:
        encryptor = AES.new(sessionKey, AES.MODE_CBC, iv=bytearray(16))
    else:
        return

    encDataframe = encryptor.encrypt(bytes(buffer))
    msg = cmd + list(encDataframe)
    handler.wfile.write(bytes([len(msg)]))
    handler.wfile.write(bytes(msg))
    handler.wfile.flush()

    statusCode = handler.rfile.read(1)[0]
    if statusCode == 0:
        # Write key to database
        connection = sqlite3.connect("keys.sqlite")
        if appId == bytes(3):
            connection.execute("insert or replace into MasterKeys (uid, keytype, key) values (?,?,?)",
                               (UID, keytype, key))
        else:
            connection.execute("insert or replace into AppKeys (uid, keytype, key, appId, name) values (?,?,?,?,?)",
                               (UID, keytype, key, appId, name))
        connection.commit()
        connection.close()
        print("Change key succesful")


def getAppId(handler: StreamRequestHandler):
    UID = handler.rfile.read(7)

    # Fetch Ids from database
    connection = sqlite3.connect("keys.sqlite")
    data = connection.execute("Select appId from AppKeys where uid=?", (UID,))

    row = data.fetchone()

    if (row is None):
        appId = bytes(3)
    else:
        appId = row[0]
    handler.wfile.write(appId)
    handler.wfile.flush()


def authenticate(handler: StreamRequestHandler):
    # Step 0: Get ID
    keytype = handler.rfile.read(1)[0]
    UID = handler.rfile.read(7)
    appId = handler.rfile.read(3)

    # Fetch key from database
    connection = sqlite3.connect("keys.sqlite")
    if appId == bytes(3):
        data = connection.execute("Select key from MasterKeys where uid=?", (UID,))
    else:
        data = connection.execute("Select key from AppKeys where uid=?", (UID,))
    row = data.fetchone()
    if (row is None):
        key = DEFAULT_KEY[0:KEYLENGTH[keytype]]
    else:
        key = row[0][0:KEYLENGTH[keytype]]
    rndSize = ROUNDSIZE[keytype]
    # Step 3
    if keytype == KEYTYPE_2K3DES:
        decryptor = DES3.new(key, DES3.MODE_CBC, iv=bytearray(8))
    elif keytype == KEYTYPE_3K3DES:
        decryptor = DES3.new(key, DES3.MODE_CBC, iv=bytearray(8))
    elif keytype == KEYTYPE_AES:
        decryptor = AES.new(key, AES.MODE_CBC, bytearray(16))
    else:
        # TODO handle
        return

    ekRndB = handler.rfile.read(rndSize)  # ek(RndB)
    RndA = get_random_bytes(rndSize)
    if (unitTest):
        RndA = TESTDATA[keytype]
    RndB = bytearray(decryptor.decrypt(ekRndB))
    RndBPrime = RndB[1:rndSize] + RndB[0:1]
    RndARndBPrime = RndA + RndBPrime

    if keytype == KEYTYPE_2K3DES:
        encryptor = DES3.new(key, DES3.MODE_CBC, iv=ekRndB)
    elif keytype == KEYTYPE_3K3DES:
        encryptor = DES3.new(key, DES3.MODE_CBC, iv=ekRndB[8:16])
    elif keytype == KEYTYPE_AES:
        encryptor = AES.new(key, AES.MODE_CBC, iv=ekRndB)
    else:
        return

    ekRndARndBPrime = encryptor.encrypt(RndARndBPrime)

    handler.wfile.write(ekRndARndBPrime)
    handler.wfile.flush()
    # Step5
    ekRndAPrime = handler.rfile.read(rndSize)

    if keytype == KEYTYPE_2K3DES:
        decryptor = DES3.new(key, DES3.MODE_CBC, iv=ekRndARndBPrime[8:16])
    elif keytype == KEYTYPE_3K3DES:
        decryptor = DES3.new(key, DES3.MODE_CBC, iv=ekRndARndBPrime[24:32])
    elif keytype == KEYTYPE_AES:
        decryptor = AES.new(key, AES.MODE_CBC, iv=ekRndARndBPrime[16:32])

    RndAPrime = decryptor.decrypt(ekRndAPrime)
    RndAPrime2 = RndA[1:rndSize] + RndA[0:1]

    if (debug):
        print("Keytype")
        print(keytype)
        print("UID")
        print(''.join('{:02x}'.format(x) for x in UID))
        print("AppId")
        print(''.join('{:02x}'.format(x) for x in appId))
        print("Key:")
        print(''.join('{:02x}'.format(x) for x in key))
        print("RndB")
        print(''.join('{:02x}'.format(x) for x in RndB))
        print("ekRndB")
        print(''.join('{:02x}'.format(x) for x in ekRndB))
        print("RndA")
        print(''.join('{:02x}'.format(x) for x in RndA))
        print("ekRndARndBPrime")
        print(''.join('{:02x}'.format(x) for x in ekRndARndBPrime))
        print("ekRndAPrime")
        print(''.join('{:02x}'.format(x) for x in ekRndAPrime))
        print("ekRndAPrime")
        print(''.join('{:02x}'.format(x) for x in RndAPrime))

    if (RndAPrime == RndAPrime2):
        print("Authenticated succesfully")
        if keytype == KEYTYPE_2K3DES:
            SessionKey = RndA[0:4] + RndB[0:4] + RndA[4:8] + RndB[4:8]
            if (key[0:8] == key[8:16]):
                SessionKey = RndA[0:4] + RndB[0:4] + RndA[0:4] + RndB[0:4]
        elif keytype == KEYTYPE_3K3DES:
            SessionKey = RndA[0:4] + RndB[0:4] + RndA[6:10] + RndB[6:10] + RndA[12:16] + RndB[12:16]
        elif keytype == KEYTYPE_AES:
            SessionKey = RndA[0:4] + RndB[0:4] + RndA[12:16] + RndB[12:16]

        sessionKeys[UID] = (keytype, SessionKey)
        if (debug):
            print("Session Key")
            print(''.join('{:02x}'.format(x) for x in SessionKey))

    else:
        print("Authenticaten failed")


if __name__ == '__main__':
    # uid = bytearray([0x04, 0x41, 0x60, 0x9A, 0xB2, 0x5D, 0x80])
    # key = bytearray([0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0])
    # connection = sqlite3.connect("keys.sqlite")
    # connection.execute("Insert into MasterKeys values (?,?,?)", (uid, KEYTYPE_AES, key))
    # connection.commit()
    # data = connection.execute("Select * from MasterKeys where uid=uid")
    # for row in data:
    #     print(''.join('{:02x}'.format(x) for x in row[0]))
    #     print(''.join('{:02x}'.format(x) for x in row[2]))
    # connection.close()


    # webServer = ThreadingTCPServer(("", 80), ConnectionHandler)
    # print("Started")
    # webServer.serve_forever()
    verifyAndroid()