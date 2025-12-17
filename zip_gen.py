#!/usr/bin/env python3

import argparse
import os
import struct
import hashlib
import hmac
import zlib
from binascii import hexlify
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Константы
SALT_LENGTH = {
    'aes128': 8,
    'aes256': 16
}

KEY_LENGTH = {
    'aes128': 16,
    'aes256': 32
}

PBKDF2_ITERATIONS = 1000

# Таблица CRC32 для ZipCrypto
CRC_TABLE = []
def init_crc_table():
    global CRC_TABLE
    for i in range(256):
        crc = i
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xEDB88320
            else:
                crc >>= 1
        CRC_TABLE.append(crc)

init_crc_table()

def crc32_byte(crc, b):
    return ((crc >> 8) ^ CRC_TABLE[(crc ^ b) & 0xff]) & 0xffffffff

def update_keys(key0, key1, key2, char):
    key0 = crc32_byte(key0, char)
    key1 = (key1 + (key0 & 0xff)) & 0xffffffff
    key1 = ((key1 * 134775813) + 1) & 0xffffffff
    key2 = crc32_byte(key2, (key1 >> 24) & 0xff)
    return key0, key1, key2

def stream_byte(key2):
    temp = (key2 | 2) & 0xffff
    return ((temp * (temp ^ 1)) >> 8) & 0xff

def generate_aes_data(password, method='aes256'):
    password_bytes = password.encode('utf-8')
    salt_len = SALT_LENGTH[method]
    salt = os.urandom(salt_len)
    key_len = KEY_LENGTH[method]
    derived = hashlib.pbkdf2_hmac('sha1', password_bytes, salt, PBKDF2_ITERATIONS, 2 * key_len + 2)
    enc_key = derived[:key_len]
    hmac_key = derived[key_len:2 * key_len]
    verify = derived[2 * key_len:]
    
    # Тестовые данные
    plaintext = b"WinZip test file content for password recovery lab"
    compressed = zlib.compress(plaintext)  # Deflate
    initial_counter = b'\x00' * 16
    cipher = Cipher(algorithms.AES(enc_key), modes.CTR(initial_counter), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(compressed) + encryptor.finalize()
    auth_code = hmac.new(hmac_key, ciphertext, hashlib.sha1).digest()[:10]
    crc = zlib.crc32(plaintext) & 0xffffffff
    crc_bytes = struct.pack('<I', crc)
    header = salt + verify
    comp = 8  # Deflate
    
    return {
        'method': method,
        'header': header,
        'ciphertext': ciphertext,
        'auth_code': auth_code,
        'crc': crc_bytes,
        'comp': comp
    }

def generate_zipcrypto_data(password):
    password_bytes = password.encode('utf-8')
    key0 = 0x12345678
    key1 = 0x23456789
    key2 = 0x34567890
    for char in password_bytes:
        key0, key1, key2 = update_keys(key0, key1, key2, char)
    
    # Тестовые данные
    plaintext = b"WinZip test file content for password recovery lab"
    compressed = zlib.compress(plaintext)
    crc = zlib.crc32(plaintext) & 0xffffffff
    
    # Plain header с двумя check bytes для снижения ложных срабатываний
    check_byte1 = (crc >> 16) & 0xff
    check_byte2 = (crc >> 24) & 0xff
    plain_header = b'\x00' * 10 + bytes([check_byte1, check_byte2])
    
    # Шифрование header
    enc_header = b''
    cur_key0, cur_key1, cur_key2 = key0, key1, key2
    for p_byte in plain_header:
        s_byte = stream_byte(cur_key2)
        e_byte = p_byte ^ s_byte
        enc_header += bytes([e_byte])
        cur_key0, cur_key1, cur_key2 = update_keys(cur_key0, cur_key1, cur_key2, p_byte)
    
    # Check value для проверки
    check_value = bytes([check_byte1, check_byte2])
    
    # Шифрование данных
    ciphertext = b''
    for p_byte in compressed:
        s_byte = stream_byte(cur_key2)
        e_byte = p_byte ^ s_byte
        ciphertext += bytes([e_byte])
        cur_key0, cur_key1, cur_key2 = update_keys(cur_key0, cur_key1, cur_key2, p_byte)
    
    crc_bytes = struct.pack('<I', crc)
    comp = 8
    
    return {
        'method': 'zipcrypto',
        'header': enc_header,
        'ciphertext': ciphertext,
        'auth_code': check_value,  # Используем как auth для унификации
        'crc': crc_bytes,
        'comp': comp
    }

def format_output(data):
    if data['method'] == 'zipcrypto':
        method_code = "0"
    elif data['method'] == 'aes128':
        method_code = "1"
    else:  # aes256
        method_code = "2"
    return "*".join([
        method_code,
        hexlify(data['header']).decode(),
        hexlify(data['ciphertext']).decode(),
        hexlify(data['auth_code']).decode(),
        hexlify(data['crc']).decode(),
        str(data['comp'])
    ])

def main():
    parser = argparse.ArgumentParser(
        description='Генератор тестовых заданий для восстановления пароля ZIP'
    )
    parser.add_argument(
        '-m', '--method',
        choices=['zipcrypto', 'aes128', 'aes256'],
        default='aes256',
        help='Метод шифрования (по умолчанию: aes256)'
    )
    parser.add_argument(
        '-p', '--password',
        required=True,
        help='Пароль для шифрования'
    )
    parser.add_argument(
        '-o', '--output',
        help='Файл для сохранения результата (опционально)'
    )
    
    args = parser.parse_args()
    
    print(f"[*] Метод шифрования: {args.method}")
    print(f"[*] Пароль: {args.password}")
    
    if args.method == 'zipcrypto':
        data = generate_zipcrypto_data(args.password)
    else:
        data = generate_aes_data(args.password, args.method)
    
    output = format_output(data)
    
    print(f"\n[+] Сгенерированные данные:")
    print(output)
    
    if args.output:
        with open(args.output, 'w') as f:
            f.write(output)
        print(f"\n[+] Данные сохранены в: {args.output}")

if __name__ == "__main__":
    main()
