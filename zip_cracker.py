#!/usr/bin/env python3

import argparse
import itertools
import multiprocessing
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
from multiprocessing import Value, Array
import ctypes

try:
    import pyzipper
    HAS_PYZIPPER = True
except ImportError:
    HAS_PYZIPPER = False
    print("[!] pyzipper not installed - AES support disabled")

ALPHABETS = {
    'a': 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',
    'd': '0123456789',
    'l': 'abcdefghijklmnopqrstuvwxyz',
    'u': 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
}

CRC_TABLE = []
def init_crc_table():
    global CRC_TABLE
    if CRC_TABLE:
        return
    for i in range(256):
        crc = i
        for _ in range(8):
            crc = (crc >> 1) ^ 0xEDB88320 if crc & 1 else crc >> 1
        CRC_TABLE.append(crc)

init_crc_table()

def crc32_byte(crc, b):
    return ((crc >> 8) ^ CRC_TABLE[(crc ^ b) & 0xff]) & 0xffffffff

def update_keys(key0, key1, key2, char):
    key0 = crc32_byte(key0, char)
    key1 = ((key1 + (key0 & 0xff)) * 134775813 + 1) & 0xffffffff
    key2 = crc32_byte(key2, (key1 >> 24) & 0xff)
    return key0, key1, key2

def stream_byte(key2):
    temp = (key2 | 2) & 0xffff
    return ((temp * (temp ^ 1)) >> 8) & 0xff

PBKDF2_ITERATIONS = 1000

# Глобальные переменные для воркеров 
_worker_data = {}

def init_worker(mode, zip_path, is_aes, sim_dict, stop_flag):
    """Инициализация воркера - выполняется один раз при старте процесса"""
    _worker_data['mode'] = mode
    _worker_data['zip_path'] = zip_path
    _worker_data['is_aes'] = is_aes
    _worker_data['stop_flag'] = stop_flag
    
    if sim_dict is not None:
        _worker_data['sim'] = sim_dict
    
    if mode == 'real':
        _worker_data['zip_handle'] = None  

def verify_zipcrypto(password_bytes, sim):
    """Оптимизированная проверка ZipCrypto"""
    key0, key1, key2 = 0x12345678, 0x23456789, 0x34567890
    
    for char in password_bytes:
        key0, key1, key2 = update_keys(key0, key1, key2, char)
    
    decrypted_header = bytearray(len(sim['header']))
    cur_key0, cur_key1, cur_key2 = key0, key1, key2
    
    for i, e_byte in enumerate(sim['header']):
        s_byte = stream_byte(cur_key2)
        p_byte = e_byte ^ s_byte
        decrypted_header[i] = p_byte
        cur_key0, cur_key1, cur_key2 = update_keys(cur_key0, cur_key1, cur_key2, p_byte)
    
    # Быстрая проверка по последним 2 байтам
    if decrypted_header[-2:] != sim['auth']:
        return False
    
    # Полная расшифровка (только если прошла быстрая проверка)
    decrypted_comp = bytearray(len(sim['ciphertext']))
    for i, e_byte in enumerate(sim['ciphertext']):
        s_byte = stream_byte(cur_key2)
        p_byte = e_byte ^ s_byte
        decrypted_comp[i] = p_byte
        cur_key0, cur_key1, cur_key2 = update_keys(cur_key0, cur_key1, cur_key2, p_byte)
    
    try:
        plaintext = zlib.decompress(bytes(decrypted_comp)) if sim['comp'] == 8 else bytes(decrypted_comp)
    except zlib.error:
        return False
    
    return (zlib.crc32(plaintext) & 0xffffffff) == sim['crc_value']

def verify_aes(password_bytes, sim):
    """Проверка AES"""
    salt = sim['header'][:-2]
    verify_given = sim['header'][-2:]
    key_len = 16 if len(salt) == 8 else 32
    
    derived = hashlib.pbkdf2_hmac('sha1', password_bytes, salt, PBKDF2_ITERATIONS, 2 * key_len + 2)
    
    # Быстрая проверка verification value
    if derived[2 * key_len:] != verify_given:
        return False
    
    enc_key = derived[:key_len]
    hmac_key = derived[key_len:2 * key_len]
    
    cipher = Cipher(algorithms.AES(enc_key), modes.CTR(b'\x00'*16), backend=default_backend())
    decryptor = cipher.decryptor()
    
    try:
        compressed = decryptor.update(sim['ciphertext']) + decryptor.finalize()
    except Exception:
        return False
    
    if hmac.new(hmac_key, sim['ciphertext'], hashlib.sha1).digest()[:10] != sim['auth']:
        return False
    
    try:
        plaintext = zlib.decompress(compressed) if sim['comp'] == 8 else compressed
    except zlib.error:
        return False
    
    return (zlib.crc32(plaintext) & 0xffffffff) == sim['crc_value']

def verify_real(password, zip_path, is_aes):
    """Проверка реального ZIP"""
    pwd_bytes = password.encode('utf-8')
    try:
        if is_aes:
            if not HAS_PYZIPPER:
                return False
            with pyzipper.AESZipFile(zip_path) as zf:
                zf.setpassword(pwd_bytes)
                for info in zf.infolist():
                    with zf.open(info) as f:
                        f.read()
        else:
            with zipfile.ZipFile(zip_path) as zf:
                for info in zf.infolist():
                    with zf.open(info, pwd=pwd_bytes) as f:
                        f.read()
        return True
    except Exception:
        return False

def worker_task(args):
    """Задача для одного воркера - обрабатывает диапазон индексов"""
    start_idx, end_idx, alphabets_tuple, mask_len = args
    
    mode = _worker_data['mode']
    stop_flag = _worker_data['stop_flag']
    
    alphabets = [list(a) for a in alphabets_tuple]
    alphabet_sizes = [len(a) for a in alphabets]
    
    local_count = 0
    batch_size = 10000 
    
    for idx in range(start_idx, end_idx):
        if local_count % batch_size == 0 and stop_flag.value:
            return (None, local_count)
        
        password_chars = []
        temp_idx = idx
        for i in range(mask_len - 1, -1, -1):
            password_chars.append(alphabets[i][temp_idx % alphabet_sizes[i]])
            temp_idx //= alphabet_sizes[i]
        password = ''.join(reversed(password_chars))
        
        local_count += 1
        
        # Проверка пароля
        if mode == 'real':
            if verify_real(password, _worker_data['zip_path'], _worker_data['is_aes']):
                return (password, local_count)
        else:
            sim = _worker_data['sim']
            password_bytes = password.encode('utf-8')
            
            if sim['method'] == 'zipcrypto':
                if verify_zipcrypto(password_bytes, sim):
                    return (password, local_count)
            else:
                if verify_aes(password_bytes, sim):
                    return (password, local_count)
    
    return (None, local_count)


class ZipCracker:
    def __init__(self, input_path):
        self.input_path = input_path
        self.is_aes = False
        self.sim_data = None
        
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
        else:
            print(f"[*] Режим: Симулированные данные")
            print(f"[*] Метод шифрования: {self.sim_data['method']}")

    def load_simulated(self, path):
        with open(path, 'r') as f:
            task_data = f.read().strip()
        parts = task_data.split('*')
        method_code = int(parts[0])
        method = {0: 'zipcrypto', 1: 'aes128', 2: 'aes256'}[method_code]
        
        crc_bytes = unhexlify(parts[4])
        
        return {
            'method': method,
            'header': unhexlify(parts[1]),
            'ciphertext': unhexlify(parts[2]),
            'auth': unhexlify(parts[3]),
            'crc_value': struct.unpack('<I', crc_bytes)[0],
            'comp': int(parts[5])
        }

    def calculate_total(self, mask):
        total = 1
        for char in mask:
            if char not in ALPHABETS:
                print(f"[!] Ошибка: неизвестный символ маски '{char}'")
                sys.exit(1)
            total *= len(ALPHABETS[char])
        return total

    def crack(self, mask, verbose=True, num_processes=None):
        if num_processes is None:
            num_processes = multiprocessing.cpu_count()
        
        total = self.calculate_total(mask)
        print(f"\n[*] Маска: {mask}")
        print(f"[*] Длина пароля: {len(mask)}")
        print(f"[*] Всего комбинаций: {total:,}")
        print(f"[*] Процессов: {num_processes}")
        print(f"\n[*] Начало перебора...\n")

        start_time = time.time()
        
        alphabets_tuple = tuple(ALPHABETS[c] for c in mask)
        
        chunk_size = max(1, total // (num_processes * 10))
        tasks = []
        for i in range(0, total, chunk_size):
            end = min(i + chunk_size, total)
            tasks.append((i, end, alphabets_tuple, len(mask)))
        
        stop_flag = Value(ctypes.c_bool, False)
        
        sim_dict = self.sim_data if self.mode == 'simulated' else None
        zip_path = self.zip_path if self.mode == 'real' else None
        
        found_password = None
        total_attempts = 0
        
        with multiprocessing.Pool(
            processes=num_processes,
            initializer=init_worker,
            initargs=(self.mode, zip_path, self.is_aes, sim_dict, stop_flag)
        ) as pool:
            
            with tqdm(total=total, unit='pwd', disable=not verbose) as pbar:
                for result in pool.imap_unordered(worker_task, tasks, chunksize=1):
                    password, count = result
                    total_attempts += count
                    pbar.update(count)
                    
                    if password is not None:
                        found_password = password
                        stop_flag.value = True
                        pool.terminate()
                        break

        elapsed = time.time() - start_time
        
        print(f"\n{'='*50}")
        if found_password:
            print(f"[+] ПАРОЛЬ НАЙДЕН: {found_password}")
            print(f"[+] Попыток: {total_attempts:,}")
        else:
            print(f"[-] Пароль НЕ НАЙДЕН")
            print(f"[-] Проверено: {total_attempts:,} паролей")
        
        print(f"[*] Время: {elapsed:.2f} сек")
        if elapsed > 0:
            print(f"[*] Скорость: {total_attempts/elapsed:,.0f} паролей/сек")
        print(f"{'='*50}")
        
        return found_password


def main():
    parser = argparse.ArgumentParser(description='Восстановление пароля ZIP по маске')
    parser.add_argument('-m', '--mask', required=True,
                        help='Маска (a=все, d=цифры, l=строчные, u=заглавные)')
    parser.add_argument('input', help='ZIP-файл или файл с данными')
    parser.add_argument('-q', '--quiet', action='store_true')
    parser.add_argument('-p', '--processes', type=int, default=None)
    
    args = parser.parse_args()
    
    print("="*50)
    print(" WinZip Password Recovery Tool")
    print("="*50)
    
    cracker = ZipCracker(args.input)
    cracker.crack(args.mask, verbose=not args.quiet, num_processes=args.processes)


if __name__ == "__main__":
    multiprocessing.freeze_support()
    main()
