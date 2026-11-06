"""
Desktop chat app written in Python (Tkinter).

1. Start the server first:   python server.py
2. Then start this app:      python client.py
   (run it twice, in two terminals, to chat between two accounts on one PC)
"""
import json
import math
import os
import queue
import re
import threading
import time
import traceback
import tkinter as tk

import requests
import websocket  # from the "websocket-client" package

import chatcrypto as cc

APP_NAME = "MyChat"  # <- change this to your app name
SERVER = os.environ.get("CHAT_SERVER", "http://localhost:5000")  # <- address of your server

GREEN, DARK, LIGHT = "#00a884", "#075e54", "#25d366"
FONT = "Segoe UI"


class ClockLogo(tk.Canvas):
    """The app logo: a clock that shows the real time."""

    def __init__(self, parent, size=90, bg="white"):
        super().__init__(parent, width=size, height=size, bg=bg, highlightthickness=0)
        self.size = size
        self.tick()

    def tick(self):
        if not self.winfo_exists():
            return
        s, c = self.size, self.size / 2
        self.delete("all")
        self.create_oval(2, 2, s - 2, s - 2, fill=GREEN, outline=GREEN)
        self.create_oval(s * 0.1, s * 0.1, s * 0.9, s * 0.9, fill="white", outline="white")
        for k in range(12):
            a = math.radians(k * 30)
            r1, r2 = c * 0.72, c * 0.82
            self.create_line(c + r1 * math.sin(a), c - r1 * math.cos(a),
                             c + r2 * math.sin(a), c - r2 * math.cos(a), fill=GREEN, width=2)
        t = time.localtime()
        hands = [((t.tm_hour % 12 + t.tm_min / 60) * 30, 0.45, 4, DARK),
                 (t.tm_min * 6, 0.65, 3, DARK),
                 (t.tm_sec * 6, 0.72, 1, LIGHT)]
        for deg, length, width, color in hands:
            a = math.radians(deg)
            self.create_line(c, c, c + c * length * math.sin(a), c - c * length * math.cos(a),
                             fill=color, width=width, capstyle="round")
        self.create_oval(c - 3, c - 3, c + 3, c + 3, fill=DARK, outline=DARK)
        self.after(1000, self.tick)


class App:
    def __init__(self, root):
        self.root = root
        root.title(APP_NAME)
        root.geometry("900x620")
        root.minsize(720, 460)
        self.q = queue.Queue()  # messages from background threads to the screen
        self.reset_state()
        self.build_login()

    def reset_state(self):
        self.mode = "login"
        self.token = self.me = self.priv = self.my_pub = self.ws = self.peer = None
        self.users, self.online, self.names, self.unread, self.keys = {}, set(), [], {}, {}
        self.base_sub, self.last_typing = "", 0

    # ------------------------------------------------------------ server calls
    def api(self, method, path, body=None):
        headers = {"Authorization": "Bearer " + self.token} if self.token else {}
        try:
            r = requests.request(method, SERVER + path, json=body, headers=headers, timeout=10)
        except requests.RequestException:
            raise RuntimeError("Cannot reach the server. Is server.py running?")
        try:
            data = r.json()
        except ValueError:
            data = {}
        if not r.ok:
            raise RuntimeError(data.get("error", "Request failed"))
        return data

    # ------------------------------------------------------------ login screen
    def build_login(self):
        self.root.configure(bg="#d1d7db")
        card = tk.Frame(self.root, bg="white", padx=36, pady=28)
        card.place(relx=0.5, rely=0.5, anchor="center")
        self.login_frame = card
        ClockLogo(card, 90).pack()
        tk.Label(card, text=APP_NAME, font=(FONT, 20, "bold"), fg=GREEN, bg="white").pack(pady=(6, 0))
        tk.Label(card, text="Private. End-to-end encrypted.", fg="#667781", bg="white").pack(pady=(0, 12))
        self.u = tk.Entry(card, width=30, font=(FONT, 11))
        self.u.pack(pady=4, ipady=5)
        self.p = tk.Entry(card, width=30, show="*", font=(FONT, 11))
        self.p.pack(pady=4, ipady=5)
        tk.Label(card, text="Username: a-z, 0-9, _ (3-20)   Password: 10+ characters",
                 fg="#8696a0", bg="white", font=(FONT, 8)).pack()
        self.go_btn = tk.Button(card, text="Log in", command=self.submit, bg=GREEN, fg="white",
                                relief="flat", padx=20, pady=6, font=(FONT, 11, "bold"))
        self.go_btn.pack(pady=(12, 4))
        self.msg = tk.Label(card, text="", fg="#c0392b", bg="white", wraplength=280)
        self.msg.pack()
        self.switch_btn = tk.Label(card, text="New here? Create an account", fg=GREEN, bg="white", cursor="hand2")
        self.switch_btn.pack(pady=(6, 0))
        self.switch_btn.bind("<Button-1>", lambda e: self.toggle_mode())
        self.p.bind("<Return>", lambda e: self.submit())
        self.u.focus()

    def say(self, text, color="#c0392b"):
        self.msg.config(text=text, fg=color)

    def toggle_mode(self):
        self.mode = "register" if self.mode == "login" else "login"
        login = self.mode == "login"
        self.go_btn.config(text="Log in" if login else "Create account")
        self.switch_btn.config(text="New here? Create an account" if login else "Already have an account? Log in")
        self.say("")

    def submit(self):
        username, password = self.u.get().strip().lower(), self.p.get()
        if not re.fullmatch(r"[a-z0-9_]{3,20}", username):
            return self.say("Username: 3-20 letters, numbers or _")
        if len(password) < 10:
            return self.say("Password must be at least 10 characters")
        self.say("Please wait...", "#667781")
        self.go_btn.config(state="disabled")
        threading.Thread(target=self.auth_worker, args=(username, password), daemon=True).start()

    def auth_worker(self, username, password):
        """Runs in a background thread so the window does not freeze."""
        try:
            wrap_key, auth = cc.derive_secrets(username, password)
            if self.mode == "register":
                priv = cc.new_private_key()
                pub = cc.public_jwk(priv.public_key())
                r = self.api("POST", "/api/register", {
                    "username": username, "auth": auth, "public_key": json.dumps(pub),
                    "wrapped_key": cc.lock_private_key(priv, wrap_key)})
            else:
                r = self.api("POST", "/api/login", {"username": username, "auth": auth})
                try:
                    priv = cc.unlock_private_key(r["wrapped_key"], wrap_key)
                except Exception:
                    raise RuntimeError("Could not unlock your keys")
                pub = json.loads(r["public_key"])
            self.q.put(("authed", username, r["token"], priv, pub))
        except Exception as e:
            self.q.put(("autherr", str(e)))

    # ------------------------------------------------------------ chat screen
    def build_chat(self):
        self.login_frame.destroy()
        self.root.configure(bg="white")
        side = tk.Frame(self.root, width=270, bg="white")
        side.pack(side="left", fill="y")
        side.pack_propagate(False)
        top = tk.Frame(side, bg="#f0f2f5")
        top.pack(fill="x")
        ClockLogo(top, 38, bg="#f0f2f5").pack(side="left", padx=8, pady=8)
        tk.Label(top, text=f"{APP_NAME}\n@{self.me}", justify="left", bg="#f0f2f5",
                 font=(FONT, 10, "bold")).pack(side="left")
        tk.Button(top, text="Log out", command=self.logout, relief="flat", bg="#f0f2f5").pack(side="right", padx=8)
        self.listbox = tk.Listbox(side, font=(FONT, 12), activestyle="none", borderwidth=0,
                                  highlightthickness=0, selectbackground="#e9edef", selectforeground="black")
        self.listbox.pack(fill="both", expand=True)
        self.listbox.bind("<<ListboxSelect>>", self.on_pick)

        main = tk.Frame(self.root, bg="#efeae2")
        main.pack(side="left", fill="both", expand=True)
        head = tk.Frame(main, bg="#f0f2f5")
        head.pack(fill="x")
        self.peer_label = tk.Label(head, text="Select a chat", font=(FONT, 12, "bold"), bg="#f0f2f5", anchor="w")
        self.peer_label.pack(fill="x", padx=12, pady=(8, 0))
        self.sub = tk.Label(head, text="", font=(FONT, 9), fg="#667781", bg="#f0f2f5", anchor="w")
        self.sub.pack(fill="x", padx=12, pady=(0, 8))

        bar = tk.Frame(main, bg="#f0f2f5")
        bar.pack(side="bottom", fill="x")
        self.entry = tk.Entry(bar, font=(FONT, 12))
        self.entry.pack(side="left", fill="x", expand=True, padx=10, pady=10, ipady=6)
        tk.Button(bar, text="Send", command=self.send, bg=GREEN, fg="white", relief="flat",
                  padx=16, pady=4).pack(side="right", padx=10)
        self.entry.bind("<Return>", lambda e: self.send())
        self.entry.bind("<Key>", self.on_key)

        self.text = tk.Text(main, state="disabled", wrap="word", bg="#efeae2", borderwidth=0,
                            highlightthickness=0, font=(FONT, 11), padx=10, pady=8)
        self.text.pack(fill="both", expand=True)
        self.text.tag_configure("me", justify="right", background="#d9fdd3", rmargin=12, spacing1=8)
        self.text.tag_configure("them", justify="left", background="#ffffff", lmargin1=12, lmargin2=12, spacing1=8)
        self.text.tag_configure("time_me", justify="right", foreground="#667781", font=(FONT, 8), rmargin=12)
        self.text.tag_configure("time_them", justify="left", foreground="#667781", font=(FONT, 8), lmargin1=12)

    def load_users_sync(self):
        r = self.api("GET", "/api/users")
        for u in r["users"]:
            self.users[u["username"]] = json.loads(u["public_key"])
        self.online = set(r["online"])
        self.refresh_list()

    def refresh_list(self):
        self.names = sorted(n for n in self.users if n != self.me)
        self.listbox.delete(0, "end")
        for i, n in enumerate(self.names):
            dot = "\u25CF" if n in self.online else "\u25CB"
            badge = f"   ({self.unread[n]} new)" if self.unread.get(n) else ""
            self.listbox.insert("end", f" {dot}  {n}{badge}")
            self.listbox.itemconfig(i, fg="#111111" if n in self.online else "#8696a0")
        if self.peer in self.names:
            self.listbox.selection_set(self.names.index(self.peer))

    def on_pick(self, _event):
        sel = self.listbox.curselection()
        if sel:
            self.open_chat(self.names[sel[0]])

    def key_for(self, peer):
        if peer not in self.keys:
            self.keys[peer] = cc.chat_key(self.priv, self.users[peer])
        return self.keys[peer]

    def open_chat(self, name):
        self.peer = name
        self.unread[name] = 0
        self.peer_label.config(text=name)
        self.text.config(state="normal")
        self.text.delete("1.0", "end")
        self.text.config(state="disabled")
        try:
            self.base_sub = "End-to-end encrypted  |  Safety code: " + cc.safety_code(self.my_pub, self.users[name])
            self.sub.config(text=self.base_sub)
            for m in self.api("GET", "/api/history/" + name)["messages"]:
                self.show(m)
        except Exception as e:
            self.sub.config(text="Error: " + str(e))
        self.refresh_list()
        self.entry.focus()

    def show(self, m):
        peer = m["receiver"] if m["sender"] == self.me else m["sender"]
        try:
            text = cc.decrypt(self.key_for(peer), m["iv"], m["ct"])
        except Exception:
            text = "(!) Could not decrypt this message"
        side = "me" if m["sender"] == self.me else "them"
        self.text.config(state="normal")
        self.text.insert("end", f" {text} ", side)
        self.text.insert("end", "\n")
        self.text.insert("end", time.strftime("%H:%M", time.localtime(m["ts"])), "time_" + side)
        self.text.insert("end", "\n")
        self.text.config(state="disabled")
        self.text.see("end")

    def send(self):
        text = self.entry.get().strip()
        if not text or not self.peer or not self.ws:
            return
        iv, ct = cc.encrypt(self.key_for(self.peer), text)
        try:
            self.ws.send(json.dumps({"type": "msg", "to": self.peer, "iv": iv, "ct": ct}))
            self.entry.delete(0, "end")
        except Exception:
            self.sub.config(text="Not connected. Trying to reconnect...")

    def on_key(self, event):
        if self.peer and self.ws and event.keysym != "Return" and time.time() - self.last_typing > 1.5:
            self.last_typing = time.time()
            try:
                self.ws.send(json.dumps({"type": "typing", "to": self.peer}))
            except Exception:
                pass

    def logout(self):
        self.token = None
        if self.ws:
            try:
                self.ws.close()
            except Exception:
                pass
        for w in self.root.winfo_children():
            w.destroy()
        self.reset_state()
        self.build_login()

    # ------------------------------------------------------------ live connection
    def ws_loop(self, token):
        url = SERVER.replace("http", "ws", 1) + "/ws"  # http -> ws, https -> wss
        while self.token == token:
            def on_open(ws):
                ws.send(json.dumps({"type": "auth", "token": token}))

            def on_message(ws, raw):
                try:
                    self.q.put(("ws", json.loads(raw)))
                except ValueError:
                    pass

            self.ws = websocket.WebSocketApp(url, on_open=on_open, on_message=on_message)
            self.ws.run_forever(ping_interval=20, ping_timeout=10)
            time.sleep(2)  # connection lost: wait, then reconnect

    def pump(self):
        """Runs every 100 ms on the screen thread and handles events from background threads."""
        try:
            while True:
                try:
                    self.handle(self.q.get_nowait())
                except queue.Empty:
                    break
                except Exception:
                    traceback.print_exc()
        finally:
            self.root.after(100, self.pump)

    def handle(self, ev):
        kind = ev[0]
        if kind == "authed":
            _, self.me, self.token, self.priv, self.my_pub = ev
            self.build_chat()
            try:
                self.load_users_sync()
            except Exception as e:
                self.sub.config(text=str(e))
            threading.Thread(target=self.ws_loop, args=(self.token,), daemon=True).start()
        elif kind == "autherr":
            self.say(ev[1])
            self.go_btn.config(state="normal")
        elif kind == "ws" and self.token:
            m, t = ev[1], ev[1].get("type")
            if t == "presence":
                self.online = set(m["online"])
                if any(n not in self.users for n in self.online):
                    self.load_users_sync()
                self.refresh_list()
            elif t == "msg":
                peer = m["receiver"] if m["sender"] == self.me else m["sender"]
                if peer not in self.users:
                    self.load_users_sync()
                if peer == self.peer:
                    self.show(m)
                elif m["sender"] != self.me:
                    self.unread[peer] = self.unread.get(peer, 0) + 1
                    self.refresh_list()
            elif t == "typing" and m.get("from") == self.peer:
                self.sub.config(text="typing...   " + self.base_sub)
                self.root.after(1500, lambda: self.sub.config(text=self.base_sub))


def main():
    root = tk.Tk()
    app = App(root)
    app.pump()
    root.mainloop()


if __name__ == "__main__":
    main()
