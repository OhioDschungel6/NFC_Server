import hashlib
import hmac
import io
from io import BytesIO
from socketserver import ThreadingTCPServer, StreamRequestHandler, TCPServer

from Crypto.Cipher import DES3
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Random import get_random_bytes
import sqlite3
import zlib
import json
from os import path
import socket
from zeroconf import Zeroconf, ServiceInfo
import RPi.GPIO as GPIO
import sched
import time

GPIO_PIN = 2

GPIO.setmode(GPIO.BCM)
# The current pin is pin nr 3 (GPIO2)
GPIO.setup(GPIO_PIN, GPIO.OUT)
GPIO.output(GPIO_PIN, False)

KEY_DATABASE = "keys.sqlite"
PRESHARED_KEY = "secretKey1234567"
PORT = 80

DEFAULT_KEY = bytearray([
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
])

# Default AES-Key

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
    KEYTYPE_3K3DES: bytearray([
        0x36, 0xC5, 0xF8, 0xBF, 0x4A, 0x09, 0xAC, 0x23, 0x9E, 0x8D, 0xA0, 0xC7, 0x32, 0x51, 0xD4, 0xAB
    ]),
    KEYTYPE_AES: bytearray([
        0xF4, 0x4B, 0x26, 0xF5, 0x68, 0x6F, 0x3A, 0x39, 0x1C, 0xD3, 0x8E, 0xBD, 0x10, 0x77, 0x22, 0x81
    ])
}

sessionKeys = {}

unitTest = False
debug = False


class ConnectionHandler(StreamRequestHandler):
    def handle(self: StreamRequestHandler):
        mode = self.rfile.read(1)[0]
        commands = {
            0xC4: ("Change key", changeKey),
            0xAA: ("Authenticate", authenticate),
            0x0D: ("Open Door", lambda handler: authenticate(handler, True)),
            0x6A: ("GetAppId", getAppId),
            0x4A: ("Verify android", verifyAndroid),
            0x56: ("Save public key", savePublicKey),
            0x6D: ("Get all devices", getAllDevices),
            0xDD: ("Delete device", deleteKey),
            0x66: ("Is key known", isKeyKnown),
            0xA6: ("Is android known", isAndroidDeviceKnown),
        }
        name, fn = commands[mode]
        print(name)
        fn(self)


def deleteKey(handler: StreamRequestHandler):
    msg = readstreamAndVerifyHMAC(handler)
    uid = msg.read(16)
    if(debug):
        logBytes("uid", uid)
    connection = sqlite3.connect(KEY_DATABASE)
    connection.execute("delete from AndroidKeys where uid = (?)", (uid,))
    connection.execute("delete from AppKeys where uid = (?)", (uid[0:7],))
    connection.commit()
    connection.close()


def readstreamAndVerifyHMAC(handler: StreamRequestHandler) -> BytesIO:
    nonce = get_random_bytes(32)
    handler.wfile.write(nonce)
    length = int.from_bytes(handler.rfile.read(4), "little")
    msg = handler.rfile.read(length)
    hmacWriter = handler.rfile.read(32)
    hmacServer = hmac.new(
        bytes(PRESHARED_KEY, 'utf-8'), msg + nonce, hashlib.sha256
    )
    if(debug):
        logBytes("Nonce", nonce)
        print("length", length)
        logBytes("msg", msg)
        logBytes("hmacWriter", hmacWriter)
    hmacSame = hmac.compare_digest(hmacServer.digest(), hmacWriter)
    if(not hmacSame):
        print("Non authentic try to write public key")
        raise PermissionError
    return io.BytesIO(msg)


def savePublicKey(handler: StreamRequestHandler):
    print("Save public key")
    msg = readstreamAndVerifyHMAC(handler)
    uid = msg.read(16)
    nameLength = msg.read(1)[0]
    name = msg.read(nameLength)
    keyLength = msg.read(1)[0]
    publicKey = msg.read(keyLength)
    connection = sqlite3.connect(KEY_DATABASE)
    connection.execute(
        "insert or replace into AndroidKeys (uid, publicKey,name) values (?,?,?)",
        (uid, publicKey, name)
    )
    connection.commit()
    connection.close()
    if(debug):
        logBytes("ID", uid)
        logBytes("PK", publicKey)


def getAllDevices(handler: StreamRequestHandler):
    connection = sqlite3.connect(KEY_DATABASE)
    androidData = connection.execute("Select uid,name from AndroidKeys")
    desfireData = connection.execute("Select uid,name from AppKeys")

    androidDeviceNames = androidData.fetchall()
    desfireDeviceNames = desfireData.fetchall()

    jsonData = {
        "desfire": [
            [toHexString(uid), name.decode("utf-8")]
            for uid, name in desfireDeviceNames
        ],
        "android": [
            [toHexString(uid), name.decode("utf-8")]
            for uid, name in androidDeviceNames
        ]
    }

    jsonStr = json.dumps(jsonData, separators=(",", ":"))
    connection.close()
    handler.wfile.write(len(jsonStr).to_bytes(4, "little"))
    handler.wfile.write(jsonStr.encode("utf-8"))


def verifyAndroid(handler: StreamRequestHandler):
    uid = handler.rfile.read(16)
    dataToSign = get_random_bytes(16)
    handler.wfile.write(dataToSign)
    connection = sqlite3.connect(KEY_DATABASE)
    data = connection.execute(
        "Select publicKey from AndroidKeys where uid=?", (uid,)
    )
    row = data.fetchone()
    connection.commit()
    connection.close()
    if row is None:
        print("Key does not exist.")
        return

    pk = row[0]

    signedDataLength = handler.rfile.read(1)[0]
    signedData = handler.rfile.read(signedDataLength)

    if(debug):
        logBytes("Data to sign", dataToSign)
        logBytes("ID", uid)
        logBytes("PK", pk)
        logBytes("Signature", signedData)

    publicKey = ECC.import_key(pk)
    hashedDataToSign = SHA256.new(dataToSign)
    verifier = DSS.new(publicKey, 'fips-186-3', encoding='der')
    try:
        verifier.verify(hashedDataToSign, bytes(signedData))
        print("Android auth succesful.")
        openDoor()
        handler.wfile.write(bytes([0x00]))
    except ValueError:
        print("Android auth failed.")
        handler.wfile.write(bytes([0xAE]))


def changeKey(handler: StreamRequestHandler):
    msg = readstreamAndVerifyHMAC(handler)
    keytype = msg.read(1)[0]
    uid = msg.read(7)
    appId = msg.read(3)
    nameLength = msg.read(1)[0]
    name = msg.read(nameLength)
    if uid not in sessionKeys:
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
        # masterkey
        # TODO set to not zero
        keyNr |= keytype
        key = bytes(keylength)
    cmd = [0xC4, keyNr]

    buffer.extend(key)
    if not isSameKey:
        # Currently not supported
        return
    if keytype == KEYTYPE_AES:
        buffer.append(keyVersion)

    # Calculate crc32 for desfire card
    crc32 = (
        zlib.crc32(bytes(cmd + buffer)) ^ 0xffffffff
    ).to_bytes(4, byteorder="little")

    buffer.extend(crc32)

    (authType, sessionKey) = sessionKeys[uid]
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
    originalDataFrameLength = bytes([len(encDataframe)])
    if(len(encDataframe) % 16 != 0):
        encDataframe = encDataframe + bytes(16 - (len(encDataframe) % 16))

    sharedKeyEncryptor = AES.new(
        bytes(PRESHARED_KEY, 'utf-8'), AES.MODE_CBC, iv=bytearray(16)
    )
    doubleEncDataframe = sharedKeyEncryptor.encrypt(bytes(encDataframe))

    handler.wfile.write(originalDataFrameLength)

    msg = cmd + list(doubleEncDataframe)
    handler.wfile.write(bytes([len(msg)]))
    handler.wfile.write(bytes(msg))
    handler.wfile.flush()

    statusCode = readstreamAndVerifyHMAC(handler).read(1)[0]
    if statusCode == 0:
        # Write key to database
        connection = sqlite3.connect(KEY_DATABASE)
        if appId == bytes(3):
            connection.execute(
                "insert or replace into MasterKeys (uid, keytype, key) values (?,?,?)",
                (uid, keytype, key)
            )
        else:
            connection.execute(
                "insert or replace into AppKeys (uid, keytype, key, appId, name) values (?,?,?,?,?)",
                (uid, keytype, key, appId, name)
            )
        connection.commit()
        connection.close()
        print("Change key succesful")


def getAppId(handler: StreamRequestHandler):
    uid = handler.rfile.read(7)

    # Fetch Ids from database
    connection = sqlite3.connect(KEY_DATABASE)
    data = connection.execute("Select appId from AppKeys where uid=?", (uid,))

    row = data.fetchone()

    if row is None:
        appId = bytes(3)
    else:
        appId = row[0]
    handler.wfile.write(appId)
    handler.wfile.flush()


def isKeyKnown(handler: StreamRequestHandler):
    uid = handler.rfile.read(7)

    # Fetch Ids from database
    connection = sqlite3.connect(KEY_DATABASE)
    data = connection.execute("Select uid from MasterKeys where uid=?", (uid,))

    row = data.fetchone()
    if row is None:
        handler.wfile.write(bytes([0]))
    else:
        handler.wfile.write(bytes([1]))

    handler.wfile.flush()


def isAndroidDeviceKnown(handler: StreamRequestHandler):
    uid = handler.rfile.read(16)

    # Fetch Ids from database
    connection = sqlite3.connect(KEY_DATABASE)
    data = connection.execute(
        "Select uid from AndroidKeys where uid=?", (uid,))

    row = data.fetchone()
    if row is None:
        handler.wfile.write(bytes([0]))
    else:
        handler.wfile.write(bytes([1]))

    handler.wfile.flush()


def authenticate(handler: StreamRequestHandler, withOpenDoor=False):
    # Step 0: Get ID
    keytype = handler.rfile.read(1)[0]
    uid = handler.rfile.read(7)
    appId = handler.rfile.read(3)

    # Fetch key from database
    connection = sqlite3.connect(KEY_DATABASE)
    if appId == bytes(3):
        data = connection.execute(
            "Select key from MasterKeys where uid=?", (uid,)
        )
    else:
        data = connection.execute(
            "Select key from AppKeys where uid=?", (uid,)
        )
    row = data.fetchone()
    if row is None:
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
        return

    ekRndB = handler.rfile.read(rndSize)  # ek(RndB)
    RndA = get_random_bytes(rndSize)
    if unitTest:
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

    if debug:
        print("Keytype")
        print(keytype)
        logBytes("UID", uid)
        logBytes("AppId", appId)
        logBytes("Key:", key)
        logBytes("RndB", RndB)
        logBytes("ekRndB", ekRndB)
        logBytes("RndA", RndA)
        logBytes("ekRndARndBPrime", ekRndARndBPrime)
        logBytes("ekRndAPrime", ekRndAPrime)

    if RndAPrime == RndAPrime2:
        print("Authenticated succesfully")
        if keytype == KEYTYPE_2K3DES:
            SessionKey = RndA[0:4] + RndB[0:4] + RndA[4:8] + RndB[4:8]
            if key[0:8] == key[8:16]:
                SessionKey = RndA[0:4] + RndB[0:4] + RndA[0:4] + RndB[0:4]
        elif keytype == KEYTYPE_3K3DES:
            SessionKey = (
                RndA[0:4] + RndB[0:4] + RndA[6:10] +
                RndB[6:10] + RndA[12:16] + RndB[12:16]
            )
        elif keytype == KEYTYPE_AES:
            SessionKey = RndA[0:4] + RndB[0:4] + RndA[12:16] + RndB[12:16]
        if withOpenDoor:
            openDoor()
        sessionKeys[uid] = (keytype, SessionKey)
        if debug:
            logBytes("Session Key", SessionKey)
        handler.wfile.write(bytes([0x00]))
        handler.wfile.flush()

    else:
        print("Authenticaten failed")
        handler.wfile.write(bytes([0xAE]))
        handler.wfile.flush()


scheduler = sched.scheduler(time.time, time.sleep)
# ledState = False


def openDoor():
    # global ledState
    # ledState = not ledState
    # GPIO.output(GPIO_PIN,ledState)
    for event in scheduler.queue:
        scheduler.cancel(event)
    GPIO.output(GPIO_PIN, True)
    scheduler.enter(5, 1, lambda: GPIO.output(GPIO_PIN, False))
    scheduler.run()


def logBytes(name: str, b: bytes):
    print(name)
    print(toHexString(b))


def toHexString(b: bytes) -> str:
    return ''.join('{:02x}'.format(x) for x in b)


def readConf():
    global PORT
    global PRESHARED_KEY
    with open(path.join(path.dirname(__file__), "config.json")) as file:
        config = json.loads(file.read())
    PORT = int(config.get("Doorserver", {}).get("port", 80))
    if "" == PORT:
        PORT = 80
    # PRESHARED_KEY = bytes.fromhex(config["secretkey"])
    # if len(PRESHARED_KEY) != 16:
    #     raise ValueError("Hexkey has to be 16 bytes long")


def getIPAdress():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip = s.getsockname()[0]
    s.close()
    return ip


if __name__ == '__main__':
    readConf()
    webServer = ThreadingTCPServer(("", PORT), ConnectionHandler)
    print("Started")
    zc = Zeroconf()
    localIp = getIPAdress()
    ipAdressAsByte = bytes([int(p) for p in localIp.split(".")])
    zc.register_service(ServiceInfo(
        "_homekeypro._tcp.local.", "dooropener._homekeypro._tcp.local.", PORT, addresses=[ipAdressAsByte]
    ))
    webServer.serve_forever()
