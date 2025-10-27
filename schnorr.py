import hashlib
from ecdsa import ellipticcurve as EC
from ecdsa.ecdsa import curve_secp256k1, generator_secp256k1
from ecdsa.numbertheory import square_root_mod_prime
from ecdsa.util import number_to_string, string_to_number
import secrets

#параметры secp256k1
p = curve_secp256k1.p()
n = generator_secp256k1.order()  
G = generator_secp256k1
curve = curve_secp256k1

def point_to_bytes(point):
    return number_to_string(point.x(), n).rjust(32, b'\x00')

def hash_schnorr(r_bytes, P_bytes, message):
    data = r_bytes + P_bytes + message
    return hashlib.sha256(data).digest()

def generate_keypair():     #генерация ключей
    privkey = secrets.randbelow(n - 1) + 1
    pubkey_point = privkey * G
    return privkey, pubkey_point

def sign_schnorr(message: bytes, privkey: int):     #генерация подписи
    
    k = secrets.randbelow(n - 1) + 1
    R = k * G
    r = R.x() % n
    r_bytes = number_to_string(r, n).rjust(32, b'\x00')

    P = privkey * G
    P_bytes = point_to_bytes(P)

    e_bytes = hash_schnorr(r_bytes, P_bytes, message)
    e = string_to_number(e_bytes) % n

    s = (k + e * privkey) % n

    return (r, s), P

def verify_schnorr(message: bytes, signature: tuple, pubkey_point: EC.Point):   #проверка подписи
    
    r, s = signature
    if not (0 < r < n and 0 < s < n):
        return False

    r_bytes = number_to_string(r, n).rjust(32, b'\x00')
    P_bytes = point_to_bytes(pubkey_point)

    e_bytes = hash_schnorr(r_bytes, P_bytes, message)
    e = string_to_number(e_bytes) % n

    sG = s * G
    eP = e * pubkey_point
    R_prime = sG + (-eP)

    if R_prime.x() is None:
        return False

    return R_prime.x() % n == r