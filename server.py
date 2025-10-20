import socket
import struct
import json
import time
import threading
import secrets
from typing import Dict
import jwt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

HOST = "0.0.0.0"
PORT = 9000

KLUCZ_JWT = b"tajny_klucz_do_tokenow"
ALG_JWT = "HS256"
CZAS_WAZNOSCI_TOKENA = 300

KLUCZ_AES = bytes.fromhex(
    "000102030405060708090a0b0c0d0e0f"
    "101112131415161718191a1b1c1d1e1f"
)

URZADZENIA: Dict[str, str] = {
    "czujnik-1": "klucz_czujnik_1",
    "czujnik-2": "klucz_czujnik_2",
}

ADMIN_KEY = "admin_secret"

ostatnie_liczniki: Dict[str, int] = {}

def odbierz_dokladnie(polaczenie: socket.socket, n: int) -> bytes:
    dane = b""
    while len(dane) < n:
        fragment = polaczenie.recv(n - len(dane))
        if not fragment:
            raise ConnectionError("Rozłączono")
        dane += fragment
    return dane

def odbierz_rame(polaczenie: socket.socket):
    naglowek = odbierz_dokladnie(polaczenie, 4)
    if naglowek == b"AUTH":
        dl = struct.unpack("!I", odbierz_dokladnie(polaczenie, 4))[0]
        tresc = odbierz_dokladnie(polaczenie, dl)
        return ("AUTH", tresc)
    elif naglowek == b"DATA":
        tok_dl = struct.unpack("!I", odbierz_dokladnie(polaczenie, 4))[0]
        token = odbierz_dokladnie(polaczenie, tok_dl)
        nonce = odbierz_dokladnie(polaczenie, 12)
        ct_dl = struct.unpack("!I", odbierz_dokladnie(polaczenie, 4))[0]
        szyfrogram = odbierz_dokladnie(polaczenie, ct_dl)
        return ("DATA", (token, nonce, szyfrogram))
    elif naglowek == b"REGI":
        dl = struct.unpack("!I", odbierz_dokladnie(polaczenie, 4))[0]
        tresc = odbierz_dokladnie(polaczenie, dl)
        return ("REGI", tresc)
    else:
        raise ValueError(f"Nieznany typ ramki: {naglowek!r}")

def wyslij_token(polaczenie: socket.socket, token: str):
    dane = token.encode("utf-8")
    polaczenie.sendall(b"TOKN" + struct.pack("!I", len(dane)) + dane)

def wyslij_odpowiedz(polaczenie: socket.socket, ok: bool, komunikat: str, extra: dict | None = None):
    obiekt = {"ok": ok, "komunikat": komunikat}
    if extra:
        obiekt.update(extra)
    dane = json.dumps(obiekt, ensure_ascii=False).encode("utf-8")
    polaczenie.sendall(b"ACKN" + struct.pack("!I", len(dane)) + dane)

def obsluz_logowanie(polaczenie: socket.socket, dane: bytes):
    try:
        req = json.loads(dane.decode("utf-8"))
        id_urzadzenia = req["id_urzadzenia"]
        klucz = req["klucz"]
    except Exception:
        wyslij_odpowiedz(polaczenie, False, "Błędny format logowania")
        return

    if URZADZENIA.get(id_urzadzenia) != klucz:
        wyslij_odpowiedz(polaczenie, False, "Niepoprawne dane logowania")
        return

    teraz = int(time.time())
    token = jwt.encode(
        {
            "idUrzadzenia": id_urzadzenia,
            "czasWydaniaTokena": teraz,
            "czasWygasniecia": teraz + CZAS_WAZNOSCI_TOKENA,
            "losowyUnikalnyIdToken": secrets.token_hex(8),
        },
        KLUCZ_JWT,
        algorithm=ALG_JWT,
    )
    wyslij_token(polaczenie, token)

def obsluz_rejestracje(polaczenie: socket.socket, dane: bytes):
    try:
        req = json.loads(dane.decode("utf-8"))
        id_new = req["id_urzadzenia"]
        klucz_new = req["klucz"]
        admin = req.get("admin_key", "")
    except Exception:
        wyslij_odpowiedz(polaczenie, False, "Błędny format rejestracji")
        return

    if admin != ADMIN_KEY:
        wyslij_odpowiedz(polaczenie, False, "Niepoprawny klucz administratora")
        return

    if id_new in URZADZENIA:
        wyslij_odpowiedz(polaczenie, False, "Urządzenie już istnieje")
        return

    URZADZENIA[id_new] = klucz_new
    wyslij_odpowiedz(polaczenie, True, f"Zarejestrowano urządzenie {id_new}")

def obsluz_dane(polaczenie: socket.socket, token: bytes, nonce: bytes, szyfrogram: bytes):
    try:
        dane_tokena = jwt.decode(token, KLUCZ_JWT, algorithms=[ALG_JWT])
        id_urzadzenia = dane_tokena["idUrzadzenia"]
    except jwt.ExpiredSignatureError:
        wyslij_odpowiedz(polaczenie, False, "Token wygasł")
        return
    except Exception as e:
        wyslij_odpowiedz(polaczenie, False, f"Błąd tokena: {e}")
        return

    try:
        aesgcm = AESGCM(KLUCZ_AES)
        plaintext = aesgcm.decrypt(nonce, szyfrogram, id_urzadzenia.encode("utf-8"))
        wiadomosc = json.loads(plaintext.decode("utf-8"))
    except Exception as e:
        wyslij_odpowiedz(polaczenie, False, f"Błąd odszyfrowania: {e}")
        return

    licznik = int(wiadomosc.get("licznik", -1))
    ostatni = ostatnie_liczniki.get(id_urzadzenia, -1)
    if licznik <= ostatni:
        wyslij_odpowiedz(polaczenie, False, f"Powtórzona wiadomość (licznik={licznik}, ostatni={ostatni})")
        return
    ostatnie_liczniki[id_urzadzenia] = licznik

    print(f"[{id_urzadzenia}] #{licznik}: {json.dumps(wiadomosc, ensure_ascii=False)}")

    wyslij_odpowiedz(polaczenie, True, "OK", {"otrzymano_licznik": licznik})

def watek_klienta(polaczenie: socket.socket, adres):
    with polaczenie:
        try:
            while True:
                typ, dane = odbierz_rame(polaczenie)
                if typ == "AUTH":
                    obsluz_logowanie(polaczenie, dane)
                elif typ == "DATA":
                    token, nonce, szyfrogram = dane
                    obsluz_dane(polaczenie, token, nonce, szyfrogram)
                elif typ == "REGI":
                    obsluz_rejestracje(polaczenie, dane)
        except (ConnectionError, OSError):
            pass

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as serwer:
        serwer.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        serwer.bind((HOST, PORT))
        serwer.listen()
        print(f"Serwer nasłuchuje na {HOST}:{PORT}")
        while True:
            polaczenie, adres = serwer.accept()
            threading.Thread(target=watek_klienta, args=(polaczenie, adres), daemon=True).start()  #

if __name__ == "__main__":
    main()
