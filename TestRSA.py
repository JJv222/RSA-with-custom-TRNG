import hashlib
import rsa
import sys

def main():
    # Wczytanie klucza publicznego i podpisu
    with open('B/public_key2.pem', 'rb') as file:
        publicKey = rsa.PublicKey.load_pkcs1_openssl_pem(file.read())
    with open('A/signature.txt', 'rb') as file:
        podpis =   file.read()

    # Wczytanie pliku i jego hash
    with open('Msg/orginal.png', 'rb') as file:
        plik = file.read()
    #hashowanie pliku
    md5_hash = hashlib.md5()
    md5_hash.update(plik)
    plikHash = md5_hash.digest()

    #Weryfikacja podpisu
    try:
        rsa.verify(plikHash, podpis, publicKey)
        IsValid = True
    except rsa.VerificationError:
        IsValid = False

    print(f"Test Hash: {plikHash.hex()}\n")
    print(f"Test Klucz Publiczny: {publicKey.save_pkcs1().hex()}\n")
    print(f"Test Podpis: {podpis.hex()}\n")
    print(f"Test Czy Poprawny? {IsValid}\n")


if __name__ == "__main__":
    main()
