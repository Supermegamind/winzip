#!/usr/bin/env python3
"""
Модуль восстановления пароля ZIP
Поддерживает реальные ZIP и симулированные данные
Добавлена поддержка AES через pyzipper (pip install pyzipper)
Исправлена проблема с multiprocessing на Windows
Требует: pip install cryptography tqdm pyzipper
"""

import argparse
import itertools
import multiprocessing
import os
import time
import sys
import zipfile
import hashlib
import hmac
import zlib
import struct
from binascii import unhexlify
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from tqdm import tqdm

try:
    import pyzipper
    HAS_PYZIPPER = True
except ImportError:
    HAS_PYZIPPER = False
    print("[!] pyzipper not installed - AES support disabled. Install with 'pip install pyzipper'")

# Алфавиты и функции ZipCrypto (остаются без изменений)
ALPHABETS = {
    'a': 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',
    'd': '0123456789',
    'l': 'abcdefghijklmnopqrstuvwxyz',
    'u': 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
}

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

PBKDF2_ITERATIONS = 1000

# Глобальные данные для симулированного режима
class SimulatedData:
    def __init__(self, method, header, ciphertext, auth, crc_given, comp):
        self.method = method
        self.header = header
        self.ciphertext = ciphertext
        self.auth = auth
        self.crc_given = crc_given
        self.comp = comp

class ZipCracker:
    def __init__(self, input_path):
        self.input_path = input_path
        if input_path.lower().endswith('.zip'):
            self.mode = 'real'
            self.zip_path = input_path
            self.is_aes = self.check_is_aes()
        else:
            self.mode = 'simulated'
            self.sim_data = self.load_simulated(input_path)
        
        self.print_info()

    def check_is_aes(self):
        with zipfile.ZipFile(self.input_path) as zf:
            return any(info.compress_type == 99 for info in zf.infolist())

    def print_info(self):
        if self.mode == 'real':
            with zipfile.ZipFile(self.input_path) as zf:
                encrypted = any(info.flag_bits & 0x1 for info in zf.infolist())
                if not encrypted:
                    print("[!] Этот ZIP-файл не зашифрован паролем")
                    sys.exit(1)
                method = 'AES' if self.is_aes else 'ZipCrypto'
                file_count = len(zf.infolist())
            print(f"[*] Режим: Реальный ZIP")
            print(f"[*] Метод шифрования: {method}")
            print(f"[*] Файлов в архиве: {file_count}")
            if self.is_aes and not HAS_PYZIPPER:
                print("[!] AES detected, but pyzipper not installed. Brute-force will fail for all passwords.")
        else:
            print(f"[*] Режим: Симулированные данные")
            print(f"[*] Метод шифрования: {self.sim_data.method}")

    def load_simulated(self, path):
        with open(path, 'r') as f:
            task_data = f.read().strip()
        parts = task_data.split('*')
        method_code = int(parts[0])
        method = {0: 'zipcrypto', 1: 'aes128', 2: 'aes256'}[method_code]
        return SimulatedData(
            method=method,
            header=unhexlify(parts[1]),
            ciphertext=unhexlify(parts[2]),
            auth=unhexlify(parts[3]),
            crc_given=unhexlify(parts[4]),
            comp=int(parts[5])
        )

    def verify_password_real(self, password):
        pwd_bytes = password.encode('utf-8')
        try:
            if self.is_aes:
                if not HAS_PYZIPPER:
                    return False
                with pyzipper.AESZipFile(self.zip_path) as zf:
                    zf.setpassword(pwd_bytes)
                    for info in zf.infolist():
                        with zf.open(info) as f:
                            f.read()  # Полная дешифровка и чтение
            else:
                with zipfile.ZipFile(self.zip_path) as zf:
                    for info in zf.infolist():
                        with zf.open(info, pwd=pwd_bytes) as f:
                            f.read()  # Полная дешифровка и чтение (проверяет CRC implicitly)
            return True
        except (RuntimeError, zipfile.BadZipFile, pyzipper.BadZipFile, Exception):
            return False

    def verify_password_simulated(self, password):
        # Остаётся без изменений (как в предыдущей версии)
        sim = self.sim_data
        password_bytes = password.encode('utf-8')
        
        if sim.method == 'zipcrypto':
            key0 = 0x12345678
            key1 = 0x23456789
            key2 = 0x34567890
            for char in password_bytes:
                key0, key1, key2 = update_keys(key0, key1, key2, char)
            cur_key0, cur_key1, cur_key2 = key0, key1, key2
            decrypted_header = []
            for e_byte in sim.header:
                s_byte = stream_byte(cur_key2)
                p_byte = e_byte ^ s_byte
                decrypted_header.append(p_byte)
                cur_key0, cur_key1, cur_key2 = update_keys(cur_key0, cur_key1, cur_key2, p_byte)
            if bytes(decrypted_header[-2:]) != sim.auth:
                return False
            decrypted_comp = b''
            for e_byte in sim.ciphertext:
                s_byte = stream_byte(cur_key2)
                p_byte = e_byte ^ s_byte
                decrypted_comp += bytes([p_byte])
                cur_key0, cur_key1, cur_key2 = update_keys(cur_key0, cur_key1, cur_key2, p_byte)
            try:
                plaintext = zlib.decompress(decrypted_comp) if sim.comp == 8 else decrypted_comp
            except zlib.error:
                return False
            return (zlib.crc32(plaintext) & 0xffffffff) == struct.unpack('<I', sim.crc_given)[0]
        
        else:  # AES
            salt = sim.header[:-2]
            verify_given = sim.header[-2:]
            key_len = 16 if len(salt) == 8 else 32
            derived = hashlib.pbkdf2_hmac('sha1', password_bytes, salt, PBKDF2_ITERATIONS, 2 * key_len + 2)
            enc_key = derived[:key_len]
            hmac_key = derived[key_len:2 * key_len]
            verify_calc = derived[2 * key_len:]
            if verify_calc != verify_given:
                return False
            cipher = Cipher(algorithms.AES(enc_key), modes.CTR(b'\x00'*16), backend=default_backend())
            decryptor = cipher.decryptor()
            try:
                compressed = decryptor.update(sim.ciphertext) + decryptor.finalize()
            except:
                return False
            auth_calc = hmac.new(hmac_key, sim.ciphertext, hashlib.sha1).digest()[:10]
            if auth_calc != sim.auth:
                return False
            try:
                plaintext = zlib.decompress(compressed) if sim.comp == 8 else compressed
            except zlib.error:
                return False
            return (zlib.crc32(plaintext) & 0xffffffff) == struct.unpack('<I', sim.crc_given)[0]

    def verify_password(self, password):
        if self.mode == 'real':
            return self.verify_password_real(password)
        else:
            return self.verify_password_simulated(password)

    def calculate_total(self, mask):
        total = 1
        for char in mask:
            if char not in ALPHABETS:
                print(f"[!] Ошибка: неизвестный символ маски '{char}'")
                sys.exit(1)
            total *= len(ALPHABETS[char])
        return total

    @staticmethod
    def crack_worker(zip_path_or_simdata, mode, is_aes, combos_chunk, queue):
        local_attempts = 0
        temp_cracker = type('Temp', (), {})
        temp_cracker.mode = mode
        if mode == 'real':
            temp_cracker.zip_path = zip_path_or_simdata
            temp_cracker.is_aes = is_aes
        else:
            temp_cracker.sim_data = zip_path_or_simdata
        
        for combo in combos_chunk:
            password = ''.join(combo)
            local_attempts += 1
            verified = (ZipCracker.verify_password_real(temp_cracker, password) if mode == 'real' 
                        else ZipCracker.verify_password_simulated(temp_cracker, password))
            if verified:
                queue.put(('found', password, local_attempts))
                return
            if local_attempts % 1000 == 0:
                queue.put(('progress', 1000))
        queue.put(('done', local_attempts))

    def crack(self, mask, verbose=True, num_processes=4):
        total = self.calculate_total(mask)
        print(f"\n[*] Маска: {mask}")
        print(f"[*] Длина пароля: {len(mask)}")
        print(f"[*] Всего комбинаций: {total:,}")
        print(f"[*] Процессов: {num_processes}")
        print(f"\n[*] Начало перебора...\n")

        self.start_time = time.time()
        self.attempts = 0

        alphabets = [ALPHABETS[c] for c in mask]
        all_combos = itertools.product(*alphabets)

        chunk_size = max(1, total // (num_processes * 20) or 1000)
        chunks = []
        current = []
        for combo in all_combos:
            current.append(combo)
            if len(current) >= chunk_size:
                chunks.append(current)
                current = []
        if current:
            chunks.append(current)

        ctx = multiprocessing.get_context('spawn')
        queue = ctx.Queue()
        processes = []

        target_data = self.zip_path if self.mode == 'real' else self.sim_data
        is_aes = self.is_aes if self.mode == 'real' else False

        for chunk in chunks:
            p = ctx.Process(
                target=ZipCracker.crack_worker,
                args=(target_data, self.mode, is_aes, chunk, queue)
            )
            processes.append(p)
            p.start()

        with tqdm(total=total, unit='pwd', disable=not verbose) as pbar:
            completed_chunks = 0
            found = False
            while completed_chunks < len(chunks) and not found:
                msg = queue.get()
                if isinstance(msg, tuple):
                    if msg[0] == 'found':
                        password = msg[1]
                        self.attempts += msg[2]
                        elapsed = time.time() - self.start_time
                        print(f"\n{'='*50}")
                        print(f"[+] ПАРОЛЬ НАЙДЕН: {password}")
                        print(f"[+] Попыток: {self.attempts:,}")
                        print(f"[+] Время: {elapsed:.2f} сек")
                        print(f"[+] Скорость: {self.attempts/elapsed:,.0f} паролей/сек" if elapsed > 0 else "")
                        print(f"{'='*50}")
                        for p in processes:
                            p.terminate()
                        found = True
                    elif msg[0] == 'progress':
                        self.attempts += msg[1]
                        pbar.update(msg[1])
                    elif msg[0] == 'done':
                        self.attempts += msg[1]
                        pbar.update(msg[1])
                        completed_chunks += 1

        for p in processes:
            p.join()

        if not found:
            elapsed = time.time() - self.start_time
            print(f"\n\n{'='*50}")
            print(f"[-] Пароль НЕ НАЙДЕН")
            print(f"[-] Проверено: {self.attempts:,} паролей")
            print(f"[-] Время: {elapsed:.2f} сек")
            print(f"{'='*50}")
        return None

def main():
    parser = argparse.ArgumentParser(
        description='Восстановление пароля ZIP по маске'
    )
    parser.add_argument(
        '-m', '--mask',
        required=True,
        help='Маска для перебора (a=все, d=цифры, l=строчные, u=заглавные)'
    )
    parser.add_argument(
        'input',
        help='Путь к ZIP-файлу (.zip) или файлу с данными задания (другой формат)'
    )
    parser.add_argument(
        '-q', '--quiet',
        action='store_true',
        help='Тихий режим (без вывода прогресса)'
    )
    parser.add_argument(
        '-p', '--processes',
        type=int,
        default=multiprocessing.cpu_count(),
        help='Количество процессов (по умолчанию: число ядер CPU)'
    )
    
    args = parser.parse_args()
    
    print("="*50)
    print(" WinZip Password Recovery Tool")
    print("="*50)
    
    cracker = ZipCracker(args.input)
    cracker.crack(args.mask, verbose=not args.quiet, num_processes=args.processes)

if __name__ == "__main__":
    multiprocessing.freeze_support()
    main()