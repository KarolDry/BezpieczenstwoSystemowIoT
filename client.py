import socket
import struct
import json
import time
import os
from typing import Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SERWER_HOST = "127.0.0.1"
SERWER_PORT = 9000

KLUCZ_AES = bytes.fromhex(
    "000102030405060708090a0b0c0d0e0f"
    "101112131415161718191a1b1c1d1e1f"
)

MAKS_PROB_LOGOWANIA = 3

def odbierz_dokladnie(polaczenie: socket.socket, n: int) -> bytes:
    dane = b""
    while len(dane) < n:
        czesc = polaczenie.recv(n - len(dane))
        if not czesc:
            raise ConnectionError("Rozłączono")
        dane += czesc
    return dane

def wyslij_logowanie(polaczenie: socket.socket, id_urzadzenia: str, klucz: str):
    tresc = json.dumps({"id_urzadzenia": id_urzadzenia, "klucz": klucz}).encode("utf-8")
    polaczenie.sendall(b"AUTH" + struct.pack("!I", len(tresc)) + tresc)

def wyslij_rejestracje(polaczenie: socket.socket, id_urzadzenia: str, klucz: str, admin_key: str):
    tresc = json.dumps({"id_urzadzenia": id_urzadzenia, "klucz": klucz, "admin_key": admin_key}).encode("utf-8")
    polaczenie.sendall(b"REGI" + struct.pack("!I", len(tresc)) + tresc)

def odbierz_token(polaczenie: socket.socket) -> Optional[str]:
    naglowek = odbierz_dokladnie(polaczenie, 4)
    if naglowek == b"TOKN":
        dl = struct.unpack("!I", odbierz_dokladnie(polaczenie, 4))[0]
        return odbierz_dokladnie(polaczenie, dl).decode("utf-8")
    elif naglowek == b"ACKN":
        dl = struct.unpack("!I", odbierz_dokladnie(polaczenie, 4))[0]
        body = json.loads(odbierz_dokladnie(polaczenie, dl).decode("utf-8"))
        print(f"Logowanie nieudane: {body.get('komunikat', 'Nieznany błąd')}")
        return None
    else:
        print(f"Nieoczekiwana ramka podczas logowania: {naglowek!r}")
        return None

def odbierz_ack(polaczenie: socket.socket) -> dict:
    naglowek = odbierz_dokladnie(polaczenie, 4)
    if naglowek != b"ACKN":
        raise RuntimeError(f"Nieoczekiwana ramka: {naglowek!r}")
    dl = struct.unpack("!I", odbierz_dokladnie(polaczenie, 4))[0]
    return json.loads(odbierz_dokladnie(polaczenie, dl).decode("utf-8"))

def wyslij_dane(polaczenie: socket.socket, token: str, id_urzadzenia: str, tresc: dict):
    aesgcm = AESGCM(KLUCZ_AES)
    nonce = os.urandom(12)
    zaszyfrowane = aesgcm.encrypt(nonce, json.dumps(tresc).encode("utf-8"), id_urzadzenia.encode("utf-8"))

    token_b = token.encode("utf-8")
    ramka = (
        b"DATA"
        + struct.pack("!I", len(token_b))
        + token_b
        + nonce
        + struct.pack("!I", len(zaszyfrowane))
        + zaszyfrowane
    )
    polaczenie.sendall(ramka)

    return odbierz_ack(polaczenie)

def tryb_interaktywny(polaczenie: socket.socket, id_urzadzenia: str, token: str):
    licznik = 0
    print("\nTryb interaktywny – wpisz wiadomość i naciśnij Enter:")
    print("  /temp <wartość>            – wysyła temperaturę")
    print("  /register <id> <klucz> <admin_key> – zarejestruj nowe urządzenie (wymaga admin_key)")
    print("  /exit                     – zakończ\n")

    while True:
        wej = input("> ").strip()
        if not wej:
            continue
        if wej in ("exit", "/exit", "koniec"):
            print("Zakończono połączenie.")
            return

        if wej.startswith("/register"):
            parts = wej.split()
            if len(parts) != 4:
                print("Użycie: /register <id> <klucz> <admin_key>")
                continue
            new_id = parts[1]
            new_key = parts[2]
            admin = parts[3]
            try:
                wyslij_rejestracje(polaczenie, new_id, new_key, admin)
                ack = odbierz_ack(polaczenie)
                print("Rejestracja:", ack)
            except Exception as e:
                print("Błąd rejestracji:", e)
            continue

        licznik += 1
        ts = int(time.time())

        if wej.startswith("/temp"):
            parts = wej.split()
            if len(parts) != 2:
                print("Użycie: /temp 23.5")
                licznik -= 1
                continue
            try:
                val = float(parts[1].replace(",", "."))
            except Exception:
                print("Błędna wartość temperatury.")
                licznik -= 1
                continue
            tresc = {
                "licznik": licznik,
                "czas": ts,
                "typ": "temperatura",
                "dane": {"wartość_C": val},
            }
        else:
            tresc = {
                "licznik": licznik,
                "czas": ts,
                "typ": "wiadomość",
                "dane": {"tekst": wej},
            }

        try:
            odp = wyslij_dane(polaczenie, token, id_urzadzenia, tresc)
            print("Odpowiedź serwera:", odp)
            if not odp.get("ok") and "Token wygasł" in odp.get("komunikat", ""):
                print("Token wygasł — zakończ program i zaloguj się ponownie.")
                return
        except Exception as e:
            print("Błąd wysyłki:", e)
            return

def main():
    print(f"Łączenie z serwerem {SERWER_HOST}:{SERWER_PORT} ...")
    for proba in range(1, MAKS_PROB_LOGOWANIA + 1):
        id_urzadzenia = input("Id urządzenia [czujnik-1]: ").strip() or "czujnik-1"
        klucz = input("Klucz [klucz_czujnik_1]: ").strip() or "klucz_czujnik_1"

        try:
            with socket.create_connection((SERWER_HOST, SERWER_PORT)) as polaczenie:
                wyslij_logowanie(polaczenie, id_urzadzenia, klucz)
                token = odbierz_token(polaczenie)
                if token:
                    print("Otrzymano token JWT:", token[:30] + "...")
                    tryb_interaktywny(polaczenie, id_urzadzenia, token)
                    return
                else:
                    pozostalo = MAKS_PROB_LOGOWANIA - proba
                    if pozostalo > 0:
                        print(f"Spróbuj ponownie ({pozostalo} prób pozostało).")
                        continue
                    else:
                        print("Wykożystano wszystkie próby logowania. Kończę.")
                        return
        except ConnectionRefusedError:
            print("Nie można połączyć się z serwerem. Sprawdź czy serwer działa.")
            return
        except Exception as e:
            print("Błąd podczas logowania:", e)
            return

if __name__ == "__main__":
    main()
