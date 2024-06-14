import hashlib
import rsa
import sys,time
import trng.final as trng
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import MD5

random_bits = trng.run_TRNG() 
index = 0
def ReadBytesFromTRNG(N):
    global index  # Dodaj to
    global random_bits
    if index == len(random_bits):
        random_bits += trng.run_TRNG()
            
    result = random_bits[index:index + (N*8)]
    index += N*8
    bytes_result = bytes(int(''.join(map(str, result[i:i+8])), 2) for i in range(0, len(result), 8))
    return bytes_result


def generateRSA():
    key = RSA.generate(3072, randfunc=ReadBytesFromTRNG)
    return key.publickey(), key

def main():
    start_time = time.time()
    publicKey, privateKey = generateRSA()
    end_time = time.time()
    czas_wykonania = end_time - start_time
    print(f"Czas Generowania Klucza: {czas_wykonania:.4f} seconds\n")

    with open('A/private_key2.pem', 'wb') as file:
        file.write(privateKey.export_key(format='PEM'))
    with open('B/public_key2.pem', 'wb') as file:
        file.write(publicKey.export_key(format='PEM'))    
    
    # Wczytanie pliku i jego hash
    with open('Msg/orginal.png', 'rb') as file:
        plik = file.read()
    #hashowanie pliku
    md5_hash = hashlib.md5()
    md5_hash.update(plik)
    plikHash= md5_hash.digest()
    
    # Tworzenie podpisu
    podpis =  pkcs1_15.new(privateKey).sign(MD5.new(plikHash))
    with open("A/signature2.txt", 'wb') as file:
        file.write(podpis)
    
    #Weryfikacja podpisu
    try:
        rsa.verify(plikHash, podpis, publicKey)
        is_valid = True
    except rsa.VerificationError:
        is_valid = False

    print(f"Orginalny Hash: {plikHash.hex()}\n")
    print(f"Podpis: {podpis.hex()}\n")
    print(f"Czy Poprawny?: {is_valid}\n")

# Run the main function
if __name__ == "__main__":
    main()
