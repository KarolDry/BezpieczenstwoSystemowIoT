import socket
import struct
import json
import time
import os
import threading
import tkinter as tk
from tkinter import simpledialog, messagebox, scrolledtext
from typing import Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SERWER_HOST = "127.0.0.1"
SERWER_PORT = 9000

KLUCZ_AES = bytes.fromhex(
    "000102030405060708090a0b0c0d0e0f"
    "101112131415161718191a1b1c1d1e1f"
)

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
    tresc = json.dumps({
        "id_urzadzenia": id_urzadzenia,
        "klucz": klucz,
        "admin_key": admin_key
    }).encode("utf-8")
    polaczenie.sendall(b"REGI" + struct.pack("!I", len(tresc)) + tresc)

def odbierz_token(polaczenie: socket.socket) -> Optional[dict]:
    naglowek = odbierz_dokladnie(polaczenie, 4)
    if naglowek == b"TOKN":
        dl = struct.unpack("!I", odbierz_dokladnie(polaczenie, 4))[0]
        dane = json.loads(odbierz_dokladnie(polaczenie, dl).decode("utf-8"))
        return dane
    elif naglowek == b"ACKN":
        dl = struct.unpack("!I", odbierz_dokladnie(polaczenie, 4))[0]
        body = json.loads(odbierz_dokladnie(polaczenie, dl).decode("utf-8"))
        messagebox.showerror("Logowanie nieudane", body.get("komunikat", "Nieznany błąd"))
        return None
    else:
        messagebox.showerror("Błąd", f"Nieoczekiwana ramka: {naglowek!r}")
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
    zaszyfrowane = aesgcm.encrypt(
        nonce,
        json.dumps(tresc).encode("utf-8"),
        id_urzadzenia.encode("utf-8")
    )
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

class KlientGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Klient IoT – GUI")

        self.polaczenie: Optional[socket.socket] = None
        self.token: Optional[str] = None
        self.id_urzadzenia: Optional[str] = None
        self.licznik = 0
        self.proby_logowania = 0


        self.frame_login = tk.Frame(self.root)
        tk.Label(self.frame_login, text="ID urządzenia:").grid(row=0, column=0, sticky="e")
        tk.Label(self.frame_login, text="Klucz:").grid(row=1, column=0, sticky="e")

        self.entry_id = tk.Entry(self.frame_login)
        self.entry_klucz = tk.Entry(self.frame_login, show="*")
        self.entry_id.grid(row=0, column=1)
        self.entry_klucz.grid(row=1, column=1)
        tk.Button(self.frame_login, text="Połącz", command=self.polacz).grid(row=2, column=0, columnspan=2, pady=5)
        self.frame_login.pack(padx=20, pady=20)


        self.frame_main = tk.Frame(self.root)
        self.text_log = scrolledtext.ScrolledText(self.frame_main, width=60, height=20, state="disabled")
        self.text_log.pack(pady=5)
        btns = tk.Frame(self.frame_main)
        tk.Button(btns, text="Temperatura", command=self.okno_temp).pack(side="left", padx=5)
        tk.Button(btns, text="Wiadomość", command=self.okno_msg).pack(side="left", padx=5)
        tk.Button(btns, text="Register", command=self.okno_register).pack(side="left", padx=5)
        tk.Button(btns, text="Wyloguj", command=self.wyloguj).pack(side="left", padx=5)
        tk.Button(btns, text="Zakończ", command=self.zamknij).pack(side="left", padx=5)
        btns.pack()


    def _log_async(self, tekst: str):
        def do_log():
            self.text_log.config(state="normal")
            self.text_log.insert(tk.END, tekst + "\n")
            self.text_log.see(tk.END)
            self.text_log.config(state="disabled")
        self.root.after(0, do_log)

    def _rozlacz_socket(self):
        try:
            if self.polaczenie:
                self.polaczenie.close()
        except Exception:
            pass
        self.polaczenie = None

    def polacz(self):
        id_urz = self.entry_id.get().strip()
        klucz = self.entry_klucz.get().strip()
        if not id_urz or not klucz:
            messagebox.showerror("Błąd", "Podaj ID urządzenia i klucz.")
            return

        try:
            self.polaczenie = socket.create_connection((SERWER_HOST, SERWER_PORT))
            wyslij_logowanie(self.polaczenie, id_urz, klucz)
            odpowiedz = odbierz_token(self.polaczenie)
            if odpowiedz:
                self.token = odpowiedz["token"]
                self.id_urzadzenia = id_urz
                self.licznik = odpowiedz.get("ostatni_licznik", 0)
                messagebox.showinfo("Sukces", f"Zalogowano pomyślnie.\nOstatni licznik: {self.licznik}")
                self.frame_login.pack_forget()
                self.frame_main.pack(padx=20, pady=20)
                self.proby_logowania = 0
            else:
                self._rozlacz_socket()
                self.proby_logowania += 1
        except Exception as e:
            messagebox.showerror("Błąd połączenia", str(e))
            self._rozlacz_socket()
            self.proby_logowania += 1

        if self.proby_logowania >= 3:
            messagebox.showwarning("Limit logowania", "Przekroczono limit logowania.")
            self.root.destroy()

    def okno_temp(self):
        if not self.polaczenie:
            messagebox.showerror("Brak połączenia", "Najpierw się zaloguj.")
            return
        val = simpledialog.askstring("Temperatura", "Podaj temperaturę (°C):", parent=self.root)
        if val is None:
            return
        try:
            val = float(val.replace(",", "."))
        except Exception:
            messagebox.showerror("Błąd", "Niepoprawna wartość temperatury.")
            return

        self.licznik += 1
        tresc = {
            "licznik": self.licznik,
            "czas": int(time.time()),
            "typ": "temperatura",
            "dane": {"wartosc_C": val},
        }
        threading.Thread(target=self._wyslij_i_loguj, args=(tresc,), daemon=True).start()

    def okno_msg(self):
        if not self.polaczenie:
            messagebox.showerror("Brak połączenia", "Najpierw się zaloguj.")
            return
        msg = simpledialog.askstring("Wiadomość", "Wpisz wiadomość do wysłania:", parent=self.root)
        if msg is None:
            return
        msg = msg.strip()
        if not msg:
            messagebox.showerror("Błąd", "Wiadomość nie może być pusta.")
            return

        self.licznik += 1
        tresc = {
            "licznik": self.licznik,
            "czas": int(time.time()),
            "typ": "wiadomosc",
            "dane": {"tekst": msg},
        }
        threading.Thread(target=self._wyslij_i_loguj, args=(tresc,), daemon=True).start()

    def okno_register(self):
        if not self.polaczenie:
            messagebox.showerror("Brak połączenia", "Najpierw się zaloguj.")
            return
        new_id = simpledialog.askstring("Rejestracja", "Nowe ID urządzenia:", parent=self.root)
        new_key = simpledialog.askstring("Rejestracja", "Klucz urządzenia:", parent=self.root)
        admin = simpledialog.askstring("Rejestracja", "Admin key:", parent=self.root)
        if not (new_id and new_key and admin):
            return
        threading.Thread(target=self._rejestruj, args=(new_id, new_key, admin), daemon=True).start()

    def _rejestruj(self, new_id, new_key, admin):
        try:
            wyslij_rejestracje(self.polaczenie, new_id, new_key, admin)
            ack = odbierz_ack(self.polaczenie)
            self._log_async(f"Rejestracja: {ack}")
        except Exception as e:
            self._log_async(f"Błąd rejestracji: {e}")

    def _wyslij_i_loguj(self, tresc):
        try:
            odp = wyslij_dane(self.polaczenie, self.token, self.id_urzadzenia, tresc)
            self._log_async(f"Odpowiedź: {odp}")
        except Exception as e:
            self._log_async(f"Błąd wysyłki: {e}")

    def wyloguj(self):
        self._rozlacz_socket()
        self.token = None
        self.id_urzadzenia = None
        self.licznik = 0
        try:
            self.frame_main.pack_forget()
        except Exception:
            pass
        self.text_log.config(state="normal")
        self.text_log.delete("1.0", tk.END)
        self.text_log.config(state="disabled")
        self.entry_id.delete(0, tk.END)
        self.entry_klucz.delete(0, tk.END)
        self.frame_login.pack(padx=20, pady=20)
        messagebox.showinfo("Wylogowano", "Zostałeś wylogowany. Możesz zalogować się na inne urządzenie.")

    def zamknij(self):
        self._rozlacz_socket()
        self.root.destroy()

def main():
    root = tk.Tk()
    app = KlientGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
