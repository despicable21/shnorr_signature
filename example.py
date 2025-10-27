#!/usr/bin/env python3
from schnorr import generate_keypair, sign_schnorr, verify_schnorr

def main():
    #тестовое сообщение
    message = b"Hello"

    #генерация ключей
    privkey, pubkey = generate_keypair()
    print(f"Приватный ключ: {hex(privkey)}")
    print(f"Публичный ключ: ({hex(pubkey.x())}, {hex(pubkey.y())})")

    #подпись сообщения
    signature, pubkey_returned = sign_schnorr(message, privkey)
    r, s = signature
    print(f"Подпись: r = {hex(r)}, s = {hex(s)}")

    #проверка подписи
    is_valid = verify_schnorr(message, signature, pubkey_returned)
    print(f"Подпись валидна: {is_valid}")

    #тест с неверным сообщением
    wrong_message = b"Hi"
    is_valid_wrong = verify_schnorr(wrong_message, signature, pubkey_returned)
    print(f"Подпись для неверного сообщения валидна: {is_valid_wrong}")

if __name__ == "__main__":
    main()